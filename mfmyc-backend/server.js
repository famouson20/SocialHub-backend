// ═══════════════════════════════════════════════════════════
//  MFM YC SocialHub — Backend Server v2 (OAuth Edition)
//  Node.js + Express
// ═══════════════════════════════════════════════════════════

require('dotenv').config();
const express   = require('express');
const cors      = require('cors');
const multer    = require('multer');
const jwt       = require('jsonwebtoken');
const bcrypt    = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const cron      = require('node-cron');
const axios     = require('axios');
const FormData  = require('form-data');
const fs        = require('fs');
const path      = require('path');

const app  = express();
const PORT = process.env.PORT || 3001;

const FRONTEND_URL  = process.env.FRONTEND_URL  || 'http://localhost:3000';
const BACKEND_URL   = process.env.BACKEND_URL   || `http://localhost:${PORT}`;
const JWT_SECRET    = process.env.JWT_SECRET    || 'fallback_dev_secret_change_me';

// ── CORS ──────────────────────────────────────────────────
app.use(cors({
  origin: [FRONTEND_URL, 'http://localhost:3000', 'http://127.0.0.1:5500'],
  credentials: true,
}));

// ── BODY PARSING ──────────────────────────────────────────
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ── FILE UPLOADS ──────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = './uploads';
    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
    cb(null, dir);
  },
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname)),
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

// ── RATE LIMITING ─────────────────────────────────────────
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));

// ── OAUTH TOKEN STORE (in-memory; use a DB in production) ─
// Stores live tokens obtained via OAuth login
const OAUTH_TOKENS = {
  facebook:  { accessToken: process.env.FB_PAGE_ACCESS_TOKEN  || null, pageId: process.env.FB_PAGE_ID || null, pageName: null },
  instagram: { accessToken: process.env.FB_PAGE_ACCESS_TOKEN  || null, igId: process.env.IG_BUSINESS_ACCOUNT_ID || null, username: null },
  youtube:   { accessToken: null, refreshToken: process.env.YOUTUBE_REFRESH_TOKEN || null, channelName: null },
  x:         { accessToken: process.env.X_ACCESS_TOKEN || null, bearerToken: process.env.X_BEARER_TOKEN || null },
  tiktok:    { accessToken: process.env.TIKTOK_ACCESS_TOKEN || null },
};

// ── USERS ─────────────────────────────────────────────────
const USERS = {
  owner: { username:'owner', email:'owner@brand.com', role:'owner', name:'Brand Owner', initials:'BO', avClass:'av-owner', passwordHash: bcrypt.hashSync('password123',10) },
  tolu:  { username:'tolu',  email:'tolu@brand.com',  role:'admin', name:'Tolu Adeyemi', initials:'TA', avClass:'av1', passwordHash: bcrypt.hashSync('admin123',10) },
  kemi:  { username:'kemi',  email:'kemi@brand.com',  role:'admin', name:'Kemi Eze',     initials:'KE', avClass:'av2', passwordHash: bcrypt.hashSync('admin123',10) },
  femi:  { username:'femi',  email:'femi@brand.com',  role:'admin', name:'Femi Balogun', initials:'FB', avClass:'av3', passwordHash: bcrypt.hashSync('admin123',10) },
  shade: { username:'shade', email:'shade@brand.com', role:'admin', name:'Shade Lawal',  initials:'SL', avClass:'av4', passwordHash: bcrypt.hashSync('admin123',10) },
};

let scheduledPosts = [];

// ── JWT MIDDLEWARE ─────────────────────────────────────────
function authMiddleware(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(header.split(' ')[1], JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}
function ownerOnly(req, res, next) {
  if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner access required' });
  next();
}

// ════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ════════════════════════════════════════════════════════════

app.post('/api/auth/login', async (req, res) => {
  try {
    const { id, password } = req.body;
    if (!id || !password) return res.status(400).json({ error: 'ID and password required' });
    const user = Object.values(USERS).find(u => u.username === id.toLowerCase() || u.email === id.toLowerCase());
    if (!user || !bcrypt.compareSync(password, user.passwordHash))
      return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ username: user.username, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '8h' });
    const { passwordHash, ...safeUser } = user;
    res.json({ token, user: safeUser });
  } catch (err) {
    res.status(500).json({ error: 'Login failed', detail: err.message });
  }
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  const user = USERS[req.user.username];
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { passwordHash, ...safeUser } = user;
  res.json(safeUser);
});

// ════════════════════════════════════════════════════════════
//  OAUTH ROUTES — Facebook & Instagram
// ════════════════════════════════════════════════════════════

// Step 1 — Redirect owner to Facebook login
app.get('/api/oauth/facebook', authMiddleware, ownerOnly, (req, res) => {
  const params = new URLSearchParams({
    client_id:     process.env.FB_APP_ID,
    redirect_uri:  `${BACKEND_URL}/api/oauth/facebook/callback`,
    scope:         'pages_manage_posts,pages_read_engagement,instagram_basic,instagram_content_publish,pages_show_list',
    response_type: 'code',
    state:         'mfmyc_fb_connect',
  });
  res.redirect(`https://www.facebook.com/v19.0/dialog/oauth?${params}`);
});

// Step 2 — Facebook sends the user back here with a code
app.get('/api/oauth/facebook/callback', async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.send(closePopup('Facebook login was cancelled.', false));

    // Exchange code for access token
    const tokenRes = await axios.get('https://graph.facebook.com/v19.0/oauth/access_token', {
      params: {
        client_id:     process.env.FB_APP_ID,
        client_secret: process.env.FB_APP_SECRET,
        redirect_uri:  `${BACKEND_URL}/api/oauth/facebook/callback`,
        code,
      },
    });
    const shortToken = tokenRes.data.access_token;

    // Exchange for long-lived token (~60 days)
    const longRes = await axios.get('https://graph.facebook.com/v19.0/oauth/access_token', {
      params: {
        grant_type:        'fb_exchange_token',
        client_id:         process.env.FB_APP_ID,
        client_secret:     process.env.FB_APP_SECRET,
        fb_exchange_token: shortToken,
      },
    });
    const longToken = longRes.data.access_token;

    // Get the user's pages
    const pagesRes = await axios.get('https://graph.facebook.com/v19.0/me/accounts', {
      params: { access_token: longToken, fields: 'id,name,access_token,instagram_business_account' },
    });
    const pages = pagesRes.data.data;
    if (!pages || !pages.length) return res.send(closePopup('No Facebook Pages found on this account.', false));

    // Use the first page (or you can let the owner pick — future enhancement)
    const page = pages[0];
    OAUTH_TOKENS.facebook.accessToken = page.access_token; // page-level token never expires
    OAUTH_TOKENS.facebook.pageId      = page.id;
    OAUTH_TOKENS.facebook.pageName    = page.name;

    // Instagram
    if (page.instagram_business_account) {
      OAUTH_TOKENS.instagram.accessToken = page.access_token;
      OAUTH_TOKENS.instagram.igId        = page.instagram_business_account.id;
      // Get IG username
      try {
        const igRes = await axios.get(`https://graph.facebook.com/v19.0/${page.instagram_business_account.id}`, {
          params: { fields: 'username', access_token: page.access_token },
        });
        OAUTH_TOKENS.instagram.username = igRes.data.username;
      } catch {}
    }

    res.send(closePopup(`Facebook Page "${page.name}" connected!${page.instagram_business_account ? ' Instagram also connected.' : ''}`, true));
  } catch (err) {
    console.error('Facebook OAuth error:', err.response?.data || err.message);
    res.send(closePopup('Facebook connection failed: ' + (err.response?.data?.error?.message || err.message), false));
  }
});

// ════════════════════════════════════════════════════════════
//  OAUTH ROUTES — YouTube (Google)
// ════════════════════════════════════════════════════════════

app.get('/api/oauth/youtube', authMiddleware, ownerOnly, (req, res) => {
  const params = new URLSearchParams({
    client_id:     process.env.YOUTUBE_CLIENT_ID,
    redirect_uri:  `${BACKEND_URL}/api/oauth/youtube/callback`,
    response_type: 'code',
    scope:         'https://www.googleapis.com/auth/youtube.upload https://www.googleapis.com/auth/youtube.readonly',
    access_type:   'offline',
    prompt:        'consent',
    state:         'mfmyc_yt_connect',
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

app.get('/api/oauth/youtube/callback', async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.send(closePopup('YouTube login was cancelled.', false));

    const tokenRes = await axios.post('https://oauth2.googleapis.com/token', {
      client_id:     process.env.YOUTUBE_CLIENT_ID,
      client_secret: process.env.YOUTUBE_CLIENT_SECRET,
      redirect_uri:  `${BACKEND_URL}/api/oauth/youtube/callback`,
      code,
      grant_type:    'authorization_code',
    });

    OAUTH_TOKENS.youtube.accessToken  = tokenRes.data.access_token;
    OAUTH_TOKENS.youtube.refreshToken = tokenRes.data.refresh_token;

    // Get channel info
    try {
      const chRes = await axios.get('https://www.googleapis.com/youtube/v3/channels', {
        params: { part: 'snippet', mine: true, access_token: OAUTH_TOKENS.youtube.accessToken },
      });
      const channel = chRes.data.items?.[0];
      if (channel) OAUTH_TOKENS.youtube.channelName = channel.snippet.title;
    } catch {}

    res.send(closePopup(`YouTube channel "${OAUTH_TOKENS.youtube.channelName || 'channel'}" connected!`, true));
  } catch (err) {
    console.error('YouTube OAuth error:', err.response?.data || err.message);
    res.send(closePopup('YouTube connection failed: ' + (err.response?.data?.error_description || err.message), false));
  }
});

// ════════════════════════════════════════════════════════════
//  OAUTH ROUTES — X (Twitter) — needs developer app first
// ════════════════════════════════════════════════════════════

app.get('/api/oauth/x', authMiddleware, ownerOnly, (req, res) => {
  // X OAuth 2.0 PKCE flow
  const params = new URLSearchParams({
    response_type:         'code',
    client_id:             process.env.X_CLIENT_ID || '',
    redirect_uri:          `${BACKEND_URL}/api/oauth/x/callback`,
    scope:                 'tweet.read tweet.write users.read offline.access',
    state:                 'mfmyc_x_connect',
    code_challenge:        'challenge',
    code_challenge_method: 'plain',
  });
  res.redirect(`https://twitter.com/i/oauth2/authorize?${params}`);
});

app.get('/api/oauth/x/callback', async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.send(closePopup('X login was cancelled.', false));

    const tokenRes = await axios.post('https://api.twitter.com/2/oauth2/token',
      new URLSearchParams({
        grant_type:    'authorization_code',
        code,
        redirect_uri:  `${BACKEND_URL}/api/oauth/x/callback`,
        code_verifier: 'challenge',
      }),
      {
        auth: { username: process.env.X_CLIENT_ID, password: process.env.X_CLIENT_SECRET },
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }
    );

    OAUTH_TOKENS.x.accessToken  = tokenRes.data.access_token;
    OAUTH_TOKENS.x.refreshToken = tokenRes.data.refresh_token;
    res.send(closePopup('X (Twitter) connected!', true));
  } catch (err) {
    console.error('X OAuth error:', err.response?.data || err.message);
    res.send(closePopup('X connection failed: ' + (err.response?.data?.error_description || err.message), false));
  }
});

// ── Helper: closes the OAuth popup and notifies the main window ──
function closePopup(message, success) {
  return `<!DOCTYPE html><html><head><title>Connecting...</title></head><body>
  <script>
    window.opener && window.opener.postMessage(
      { type: 'OAUTH_RESULT', success: ${success}, message: ${JSON.stringify(message)} },
      '*'
    );
    window.close();
  <\/script>
  <p style="font-family:sans-serif;padding:20px">${message}</p>
  </body></html>`;
}

// ── GET /api/oauth/status — returns which platforms are connected ──
app.get('/api/oauth/status', authMiddleware, (req, res) => {
  res.json({
    facebook:  { connected: !!OAUTH_TOKENS.facebook.accessToken,  name: OAUTH_TOKENS.facebook.pageName  || null },
    instagram: { connected: !!OAUTH_TOKENS.instagram.igId,         name: OAUTH_TOKENS.instagram.username || null },
    youtube:   { connected: !!(OAUTH_TOKENS.youtube.accessToken || OAUTH_TOKENS.youtube.refreshToken), name: OAUTH_TOKENS.youtube.channelName || null },
    x:         { connected: !!OAUTH_TOKENS.x.accessToken,          name: null },
    tiktok:    { connected: !!OAUTH_TOKENS.tiktok.accessToken,     name: null },
  });
});

// ════════════════════════════════════════════════════════════
//  AI CAPTION
// ════════════════════════════════════════════════════════════

app.post('/api/ai/caption', authMiddleware, async (req, res) => {
  try {
    const { prompt, platforms } = req.body;
    if (!prompt) return res.status(400).json({ error: 'Prompt is required' });
    const r = await axios.post('https://api.anthropic.com/v1/messages',
      { model:'claude-sonnet-4-20250514', max_tokens:1000, messages:[{ role:'user', content:`Write a social media caption for: ${prompt}. Platforms: ${(platforms||[]).join(', ')}. Make it engaging, punchy, under 220 characters. Return only the caption text.` }] },
      { headers:{ 'Content-Type':'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version':'2023-06-01' } }
    );
    res.json({ caption: r.data.content?.[0]?.text || '' });
  } catch (err) {
    res.status(500).json({ error: 'Caption generation failed' });
  }
});

// ════════════════════════════════════════════════════════════
//  POST ROUTES
// ════════════════════════════════════════════════════════════

app.post('/api/post', authMiddleware, upload.single('media'), async (req, res) => {
  try {
    const { text, platforms } = req.body;
    const platList  = JSON.parse(platforms || '[]');
    const mediaPath = req.file ? req.file.path : null;
    if (!text) return res.status(400).json({ error: 'Post text is required' });

    const results = {}, errors = {};
    await Promise.allSettled(platList.map(async (p) => {
      try {
        switch(p) {
          case 'Facebook':  results.Facebook  = await postToFacebook(text, mediaPath);  break;
          case 'Instagram': results.Instagram = await postToInstagram(text, mediaPath); break;
          case 'X':         results.X         = await postToX(text, mediaPath);         break;
          case 'TikTok':    results.TikTok    = await postToTikTok(text, mediaPath);    break;
          case 'YouTube':   results.YouTube   = await postToYouTube(text, mediaPath);   break;
          default: errors[p] = 'Unknown platform';
        }
      } catch(e) { errors[p] = e.message; }
    }));

    if (mediaPath && fs.existsSync(mediaPath)) fs.unlinkSync(mediaPath);
    res.json({ success: true, posted: Object.keys(results), failed: errors, results });
  } catch (err) {
    res.status(500).json({ error: 'Posting failed', detail: err.message });
  }
});

app.post('/api/schedule', authMiddleware, (req, res) => {
  try {
    const { text, platforms, scheduledAt } = req.body;
    if (!text || !platforms || !scheduledAt) return res.status(400).json({ error: 'text, platforms, and scheduledAt required' });
    const job = { id: Date.now(), text, platforms: JSON.parse(platforms), scheduledAt: new Date(scheduledAt), admin: req.user.name, initials: USERS[req.user.username]?.initials, avClass: USERS[req.user.username]?.avClass, status: 'pending', createdAt: new Date() };
    scheduledPosts.push(job);
    res.json({ success: true, job });
  } catch (err) { res.status(500).json({ error: 'Scheduling failed' }); }
});

app.get('/api/schedule',       authMiddleware, (req, res) => res.json(scheduledPosts));
app.delete('/api/schedule/:id', authMiddleware, (req, res) => {
  scheduledPosts = scheduledPosts.filter(j => j.id !== parseInt(req.params.id));
  res.json({ success: true });
});

// ════════════════════════════════════════════════════════════
//  ADMIN MANAGEMENT
// ════════════════════════════════════════════════════════════

app.get('/api/admins', authMiddleware, ownerOnly, (req, res) => {
  res.json(Object.values(USERS).filter(u => u.role==='admin').map(({ passwordHash, ...u }) => u));
});

app.post('/api/admins', authMiddleware, ownerOnly, (req, res) => {
  const { username, email, name, password } = req.body;
  if (!username || !email || !name || !password) return res.status(400).json({ error: 'All fields required' });
  if (USERS[username]) return res.status(409).json({ error: 'Username already exists' });
  const avClasses = ['av1','av2','av3','av4'];
  const adminCount = Object.values(USERS).filter(u => u.role==='admin').length;
  USERS[username] = { username, email, name, role:'admin', initials: name.split(' ').map(w=>w[0]).join('').substring(0,2).toUpperCase(), avClass: avClasses[adminCount%4], passwordHash: bcrypt.hashSync(password, 10) };
  const { passwordHash, ...safeUser } = USERS[username];
  res.json({ success: true, user: safeUser });
});

app.delete('/api/admins/:username', authMiddleware, ownerOnly, (req, res) => {
  if (!USERS[req.params.username]) return res.status(404).json({ error: 'Admin not found' });
  if (USERS[req.params.username].role === 'owner') return res.status(403).json({ error: 'Cannot remove owner' });
  delete USERS[req.params.username];
  res.json({ success: true });
});

// ════════════════════════════════════════════════════════════
//  PLATFORM POSTING FUNCTIONS
// ════════════════════════════════════════════════════════════

async function postToFacebook(text, mediaPath) {
  const { accessToken, pageId } = OAUTH_TOKENS.facebook;
  if (!accessToken || !pageId) throw new Error('Facebook not connected — please connect via the Accounts page');
  if (mediaPath) {
    const form = new FormData();
    form.append('message', text);
    form.append('source', fs.createReadStream(mediaPath));
    form.append('access_token', accessToken);
    const r = await axios.post(`https://graph.facebook.com/v19.0/${pageId}/photos`, form, { headers: form.getHeaders() });
    return { id: r.data.id };
  }
  const r = await axios.post(`https://graph.facebook.com/v19.0/${pageId}/feed`, { message: text, access_token: accessToken });
  return { id: r.data.id };
}

async function postToInstagram(text, mediaPath) {
  const { accessToken, igId } = OAUTH_TOKENS.instagram;
  if (!accessToken || !igId) throw new Error('Instagram not connected — please connect via the Accounts page');
  if (!mediaPath) throw new Error('Instagram requires an image or video');
  const imageUrl = `${BACKEND_URL}/uploads/${path.basename(mediaPath)}`;
  const containerRes = await axios.post(`https://graph.facebook.com/v19.0/${igId}/media`, { image_url: imageUrl, caption: text, access_token: accessToken });
  const publishRes   = await axios.post(`https://graph.facebook.com/v19.0/${igId}/media_publish`, { creation_id: containerRes.data.id, access_token: accessToken });
  return { id: publishRes.data.id };
}

async function refreshYouTubeToken() {
  if (!OAUTH_TOKENS.youtube.refreshToken) throw new Error('YouTube not connected');
  const r = await axios.post('https://oauth2.googleapis.com/token', {
    client_id: process.env.YOUTUBE_CLIENT_ID, client_secret: process.env.YOUTUBE_CLIENT_SECRET,
    refresh_token: OAUTH_TOKENS.youtube.refreshToken, grant_type: 'refresh_token',
  });
  OAUTH_TOKENS.youtube.accessToken = r.data.access_token;
  return r.data.access_token;
}

async function postToYouTube(text, mediaPath) {
  if (!OAUTH_TOKENS.youtube.refreshToken) throw new Error('YouTube not connected — please connect via the Accounts page');
  if (!mediaPath) throw new Error('YouTube requires a video file');
  const accessToken = await refreshYouTubeToken();
  const fileStream  = fs.createReadStream(mediaPath);
  const fileSize    = fs.statSync(mediaPath).size;
  const initRes = await axios.post(
    'https://www.googleapis.com/upload/youtube/v3/videos?uploadType=resumable&part=snippet,status',
    { snippet: { title: text.substring(0,100), description: text, categoryId:'22' }, status: { privacyStatus:'public' } },
    { headers: { Authorization:`Bearer ${accessToken}`, 'Content-Type':'application/json', 'X-Upload-Content-Type':'video/mp4', 'X-Upload-Content-Length': fileSize } }
  );
  const videoRes = await axios.put(initRes.headers.location, fileStream, {
    headers: { 'Content-Type':'video/mp4', 'Content-Length': fileSize, Authorization:`Bearer ${accessToken}` },
    maxBodyLength: Infinity, maxContentLength: Infinity,
  });
  return { id: videoRes.data.id, url: `https://youtu.be/${videoRes.data.id}` };
}

async function postToX(text, mediaPath) {
  const token = OAUTH_TOKENS.x.accessToken || OAUTH_TOKENS.x.bearerToken;
  if (!token) throw new Error('X not connected — please connect via the Accounts page');
  const r = await axios.post('https://api.twitter.com/2/tweets', { text },
    { headers: { Authorization:`Bearer ${token}`, 'Content-Type':'application/json' } }
  );
  return { id: r.data.data.id };
}

async function postToTikTok(text, mediaPath) {
  const { accessToken } = OAUTH_TOKENS.tiktok;
  if (!accessToken) throw new Error('TikTok not connected — please configure via .env');
  if (!mediaPath) throw new Error('TikTok requires a video file');
  const initRes = await axios.post('https://open.tiktokapis.com/v2/post/publish/inbox/video/init/',
    { post_info:{ title: text.substring(0,150), privacy_level:'PUBLIC_TO_EVERYONE', disable_duet:false, disable_comment:false, disable_stitch:false },
      source_info:{ source:'FILE_UPLOAD', video_size: fs.statSync(mediaPath).size, chunk_size: fs.statSync(mediaPath).size, total_chunk_count:1 } },
    { headers:{ Authorization:`Bearer ${accessToken}`, 'Content-Type':'application/json; charset=UTF-8' } }
  );
  const videoBuffer = fs.readFileSync(mediaPath);
  await axios.put(initRes.data.data.upload_url, videoBuffer, { headers:{ 'Content-Type':'video/mp4', 'Content-Range':`bytes 0-${videoBuffer.length-1}/${videoBuffer.length}` } });
  return { publishId: initRes.data.data.publish_id };
}

// ── CRON — scheduled posts ─────────────────────────────────
cron.schedule('* * * * *', async () => {
  const now = new Date();
  const due = scheduledPosts.filter(j => j.status==='pending' && new Date(j.scheduledAt) <= now);
  for (const job of due) {
    job.status = 'running';
    const results = {}, errors = {};
    await Promise.allSettled(job.platforms.map(async p => {
      try {
        switch(p) {
          case 'Facebook':  results.Facebook  = await postToFacebook(job.text, null);  break;
          case 'Instagram': results.Instagram = await postToInstagram(job.text, null); break;
          case 'X':         results.X         = await postToX(job.text, null);         break;
          case 'TikTok':    results.TikTok    = await postToTikTok(job.text, null);    break;
          case 'YouTube':   results.YouTube   = await postToYouTube(job.text, null);   break;
        }
      } catch(e) { errors[p] = e.message; }
    }));
    job.status = 'done'; job.results = results; job.errors = errors;
  }
});

// ── HEALTH CHECK ──────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({
  status: 'ok', app: 'MFM YC SocialHub', time: new Date().toISOString(),
  connected: {
    facebook:  !!OAUTH_TOKENS.facebook.accessToken,
    instagram: !!OAUTH_TOKENS.instagram.igId,
    youtube:   !!(OAUTH_TOKENS.youtube.accessToken || OAUTH_TOKENS.youtube.refreshToken),
    x:         !!OAUTH_TOKENS.x.accessToken,
    tiktok:    !!OAUTH_TOKENS.tiktok.accessToken,
  },
}));

// ── Serve uploads publicly (for Instagram image URLs) ─────
app.use('/uploads', express.static('uploads'));

app.listen(PORT, () => console.log(`\n🔥 MFM YC SocialHub backend on port ${PORT}\n   Health: http://localhost:${PORT}/api/health\n`));
