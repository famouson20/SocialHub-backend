// ═══════════════════════════════════════════════════════════
//  MFM YC SocialHub — Backend Server
//  Node.js + Express
// ═══════════════════════════════════════════════════════════

require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const multer     = require('multer');
const jwt        = require('jsonwebtoken');
const bcrypt     = require('bcryptjs');
const rateLimit  = require('express-rate-limit');
const cron       = require('node-cron');
const axios      = require('axios');
const FormData   = require('form-data');
const fs         = require('fs');
const path       = require('path');

const app  = express();
const PORT = process.env.PORT || 3001;

// ── CORS ─────────────────────────────────────────────────────
app.use(cors({
  origin: [
    process.env.FRONTEND_URL,
    'http://localhost:3000',
    'http://127.0.0.1:5500',  // Live Server for local dev
  ],
  credentials: true,
}));

// ── BODY PARSING ──────────────────────────────────────────────
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ── FILE UPLOADS (images/media) ───────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = './uploads';
    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } }); // 50MB

// ── RATE LIMITING ─────────────────────────────────────────────
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use(limiter);

// ── IN-MEMORY USERS (replace with a DB in production) ─────────
// Passwords are bcrypt hashed. Generate a new hash:
//   node -e "const b=require('bcryptjs');console.log(b.hashSync('yourpassword',10))"
const USERS = {
  owner: {
    username: 'owner',
    email: 'owner@brand.com',
    role: 'owner',
    name: 'Brand Owner',
    initials: 'BO',
    avClass: 'av-owner',
    // Default hash for 'password123' — CHANGE THIS
    passwordHash: bcrypt.hashSync('password123', 10),
  },
  tolu: {
    username: 'tolu',
    email: 'tolu@brand.com',
    role: 'admin',
    name: 'Tolu Adeyemi',
    initials: 'TA',
    avClass: 'av1',
    passwordHash: bcrypt.hashSync('admin123', 10),
  },
  kemi: {
    username: 'kemi',
    email: 'kemi@brand.com',
    role: 'admin',
    name: 'Kemi Eze',
    initials: 'KE',
    avClass: 'av2',
    passwordHash: bcrypt.hashSync('admin123', 10),
  },
  femi: {
    username: 'femi',
    email: 'femi@brand.com',
    role: 'admin',
    name: 'Femi Balogun',
    initials: 'FB',
    avClass: 'av3',
    passwordHash: bcrypt.hashSync('admin123', 10),
  },
  shade: {
    username: 'shade',
    email: 'shade@brand.com',
    role: 'admin',
    name: 'Shade Lawal',
    initials: 'SL',
    avClass: 'av4',
    passwordHash: bcrypt.hashSync('admin123', 10),
  },
};

// ── SCHEDULED POSTS STORE (replace with DB in production) ─────
let scheduledPosts = [];

// ── JWT MIDDLEWARE ─────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'No token provided' });
  const token = header.split(' ')[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'fallback_dev_secret');
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function ownerOnly(req, res, next) {
  if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner access required' });
  next();
}

// ════════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ════════════════════════════════════════════════════════════════

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { id, password } = req.body;
    if (!id || !password) return res.status(400).json({ error: 'ID and password required' });

    // Find user by username or email
    const user = Object.values(USERS).find(
      u => u.username === id.toLowerCase() || u.email === id.toLowerCase()
    );

    if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { username: user.username, role: user.role, name: user.name },
      process.env.JWT_SECRET || 'fallback_dev_secret',
      { expiresIn: '8h' }
    );

    const { passwordHash, ...safeUser } = user;
    res.json({ token, user: safeUser });
  } catch (err) {
    res.status(500).json({ error: 'Login failed', detail: err.message });
  }
});

// GET /api/auth/me  — verify token & return user
app.get('/api/auth/me', authMiddleware, (req, res) => {
  const user = USERS[req.user.username];
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { passwordHash, ...safeUser } = user;
  res.json(safeUser);
});

// ════════════════════════════════════════════════════════════════
//  AI CAPTION ROUTE (proxies Anthropic so key stays server-side)
// ════════════════════════════════════════════════════════════════

// POST /api/ai/caption
app.post('/api/ai/caption', authMiddleware, async (req, res) => {
  try {
    const { prompt, platforms } = req.body;
    if (!prompt) return res.status(400).json({ error: 'Prompt is required' });

    const response = await axios.post(
      'https://api.anthropic.com/v1/messages',
      {
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1000,
        messages: [{
          role: 'user',
          content: `Write a social media caption for: ${prompt}. Platforms: ${(platforms || []).join(', ')}. Make it engaging, punchy, under 220 characters. Return only the caption text.`,
        }],
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': process.env.ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
        },
      }
    );

    const caption = response.data.content?.[0]?.text || '';
    res.json({ caption });
  } catch (err) {
    console.error('AI caption error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Caption generation failed' });
  }
});

// ════════════════════════════════════════════════════════════════
//  POSTING ROUTES
// ════════════════════════════════════════════════════════════════

// POST /api/post  — main posting endpoint
app.post('/api/post', authMiddleware, upload.single('media'), async (req, res) => {
  try {
    const { text, platforms } = req.body;
    const platList = JSON.parse(platforms || '[]');
    const mediaPath = req.file ? req.file.path : null;

    if (!text) return res.status(400).json({ error: 'Post text is required' });
    if (!platList.length) return res.status(400).json({ error: 'Select at least one platform' });

    const results = {};
    const errors  = {};

    // Post to each selected platform in parallel
    await Promise.allSettled(
      platList.map(async (platform) => {
        try {
          switch (platform) {
            case 'Facebook':
              results.Facebook  = await postToFacebook(text, mediaPath);
              break;
            case 'Instagram':
              results.Instagram = await postToInstagram(text, mediaPath);
              break;
            case 'X':
              results.X         = await postToX(text, mediaPath);
              break;
            case 'TikTok':
              results.TikTok    = await postToTikTok(text, mediaPath);
              break;
            case 'YouTube':
              results.YouTube   = await postToYouTube(text, mediaPath);
              break;
            default:
              errors[platform]  = 'Unknown platform';
          }
        } catch (e) {
          errors[platform] = e.message;
        }
      })
    );

    // Clean up uploaded file
    if (mediaPath && fs.existsSync(mediaPath)) fs.unlinkSync(mediaPath);

    res.json({
      success: true,
      posted: Object.keys(results),
      failed: errors,
      results,
    });
  } catch (err) {
    console.error('Post error:', err.message);
    res.status(500).json({ error: 'Posting failed', detail: err.message });
  }
});

// POST /api/schedule  — save a scheduled post
app.post('/api/schedule', authMiddleware, (req, res) => {
  try {
    const { text, platforms, scheduledAt } = req.body;
    if (!text || !platforms || !scheduledAt)
      return res.status(400).json({ error: 'text, platforms, and scheduledAt are required' });

    const job = {
      id: Date.now(),
      text,
      platforms: JSON.parse(platforms),
      scheduledAt: new Date(scheduledAt),
      admin: req.user.name,
      initials: USERS[req.user.username]?.initials,
      avClass: USERS[req.user.username]?.avClass,
      status: 'pending',
      createdAt: new Date(),
    };

    scheduledPosts.push(job);
    res.json({ success: true, job });
  } catch (err) {
    res.status(500).json({ error: 'Scheduling failed', detail: err.message });
  }
});

// GET /api/schedule  — list all scheduled posts
app.get('/api/schedule', authMiddleware, (req, res) => {
  res.json(scheduledPosts);
});

// DELETE /api/schedule/:id
app.delete('/api/schedule/:id', authMiddleware, (req, res) => {
  scheduledPosts = scheduledPosts.filter(j => j.id !== parseInt(req.params.id));
  res.json({ success: true });
});

// ════════════════════════════════════════════════════════════════
//  ADMIN MANAGEMENT (owner only)
// ════════════════════════════════════════════════════════════════

// GET /api/admins
app.get('/api/admins', authMiddleware, ownerOnly, (req, res) => {
  const admins = Object.values(USERS)
    .filter(u => u.role === 'admin')
    .map(({ passwordHash, ...u }) => u);
  res.json(admins);
});

// POST /api/admins  — add admin
app.post('/api/admins', authMiddleware, ownerOnly, (req, res) => {
  try {
    const { username, email, name, role, password } = req.body;
    if (!username || !email || !name || !password)
      return res.status(400).json({ error: 'username, email, name, and password are required' });
    if (USERS[username]) return res.status(409).json({ error: 'Username already exists' });

    const avClasses = ['av1','av2','av3','av4'];
    const adminCount = Object.values(USERS).filter(u => u.role === 'admin').length;
    USERS[username] = {
      username,
      email,
      name,
      role: 'admin',
      initials: name.split(' ').map(w => w[0]).join('').substring(0,2).toUpperCase(),
      avClass: avClasses[adminCount % 4],
      passwordHash: bcrypt.hashSync(password, 10),
    };

    const { passwordHash, ...safeUser } = USERS[username];
    res.json({ success: true, user: safeUser });
  } catch (err) {
    res.status(500).json({ error: 'Failed to add admin', detail: err.message });
  }
});

// DELETE /api/admins/:username
app.delete('/api/admins/:username', authMiddleware, ownerOnly, (req, res) => {
  const { username } = req.params;
  if (!USERS[username]) return res.status(404).json({ error: 'Admin not found' });
  if (USERS[username].role === 'owner') return res.status(403).json({ error: 'Cannot remove owner' });
  delete USERS[username];
  res.json({ success: true });
});

// ════════════════════════════════════════════════════════════════
//  PLATFORM CONNECTOR FUNCTIONS
// ════════════════════════════════════════════════════════════════

// ── FACEBOOK ──────────────────────────────────────────────────
async function postToFacebook(text, mediaPath) {
  const pageId    = process.env.FB_PAGE_ID;
  const token     = process.env.FB_PAGE_ACCESS_TOKEN;

  if (!pageId || !token) throw new Error('Facebook credentials not configured');

  if (mediaPath) {
    // Post with image
    const form = new FormData();
    form.append('message', text);
    form.append('source', fs.createReadStream(mediaPath));
    form.append('access_token', token);

    const r = await axios.post(
      `https://graph.facebook.com/v19.0/${pageId}/photos`,
      form,
      { headers: form.getHeaders() }
    );
    return { id: r.data.id, url: `https://facebook.com/${r.data.id}` };
  } else {
    // Text-only post
    const r = await axios.post(
      `https://graph.facebook.com/v19.0/${pageId}/feed`,
      { message: text, access_token: token }
    );
    return { id: r.data.id };
  }
}

// ── INSTAGRAM ────────────────────────────────────────────────
async function postToInstagram(text, mediaPath) {
  const igId  = process.env.IG_BUSINESS_ACCOUNT_ID;
  const token = process.env.FB_PAGE_ACCESS_TOKEN; // Same token as Facebook

  if (!igId || !token) throw new Error('Instagram credentials not configured');
  if (!mediaPath) throw new Error('Instagram requires an image');

  // Step 1: Upload media container
  // Note: image must be publicly accessible. In production, upload to your server first.
  // For now, we use a publicly hosted image URL approach.
  // You would need to serve the uploaded image via a public URL.
  const imageUrl = `${process.env.FRONTEND_URL}/uploads/${path.basename(mediaPath)}`;

  const containerRes = await axios.post(
    `https://graph.facebook.com/v19.0/${igId}/media`,
    { image_url: imageUrl, caption: text, access_token: token }
  );
  const containerId = containerRes.data.id;

  // Step 2: Publish the container
  const publishRes = await axios.post(
    `https://graph.facebook.com/v19.0/${igId}/media_publish`,
    { creation_id: containerId, access_token: token }
  );

  return { id: publishRes.data.id };
}

// ── X (TWITTER) ───────────────────────────────────────────────
async function postToX(text, mediaPath) {
  const apiKey    = process.env.X_API_KEY;
  const apiSecret = process.env.X_API_SECRET;
  const accToken  = process.env.X_ACCESS_TOKEN;
  const accSecret = process.env.X_ACCESS_TOKEN_SECRET;

  if (!apiKey || !accToken) throw new Error('X credentials not configured');

  // For X API v2 we need OAuth 1.0a — using a simple oauth helper
  // In production install: npm install oauth-1.0a crypto
  // For now we call the v2 endpoint with Bearer token for text posts
  const bearerToken = process.env.X_BEARER_TOKEN;

  const payload = { text };

  // If media, upload it first (requires OAuth 1.0a — stub here)
  if (mediaPath) {
    // Media upload requires twitter-api-v2 library for full support
    // This is a text-only fallback
    console.warn('X media upload requires twitter-api-v2 library — posting text only');
  }

  const r = await axios.post(
    'https://api.twitter.com/2/tweets',
    payload,
    {
      headers: {
        'Authorization': `Bearer ${bearerToken}`,
        'Content-Type': 'application/json',
      },
    }
  );

  return { id: r.data.data.id };
}

// ── TIKTOK ───────────────────────────────────────────────────
async function postToTikTok(text, mediaPath) {
  const accessToken = process.env.TIKTOK_ACCESS_TOKEN;
  if (!accessToken) throw new Error('TikTok credentials not configured');
  if (!mediaPath) throw new Error('TikTok requires a video file');

  // TikTok Content Posting API — initialize upload
  const initRes = await axios.post(
    'https://open.tiktokapis.com/v2/post/publish/inbox/video/init/',
    {
      post_info: {
        title: text.substring(0, 150),
        privacy_level: 'PUBLIC_TO_EVERYONE',
        disable_duet: false,
        disable_comment: false,
        disable_stitch: false,
      },
      source_info: {
        source: 'FILE_UPLOAD',
        video_size: fs.statSync(mediaPath).size,
        chunk_size: fs.statSync(mediaPath).size,
        total_chunk_count: 1,
      },
    },
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json; charset=UTF-8',
      },
    }
  );

  const uploadUrl   = initRes.data.data.upload_url;
  const publishId   = initRes.data.data.publish_id;
  const videoBuffer = fs.readFileSync(mediaPath);

  // Upload the video chunk
  await axios.put(uploadUrl, videoBuffer, {
    headers: {
      'Content-Type': 'video/mp4',
      'Content-Range': `bytes 0-${videoBuffer.length - 1}/${videoBuffer.length}`,
    },
  });

  return { publishId };
}

// ── YOUTUBE ───────────────────────────────────────────────────
async function postToYouTube(text, mediaPath) {
  const clientId     = process.env.YOUTUBE_CLIENT_ID;
  const clientSecret = process.env.YOUTUBE_CLIENT_SECRET;
  const refreshToken = process.env.YOUTUBE_REFRESH_TOKEN;

  if (!clientId || !refreshToken) throw new Error('YouTube credentials not configured');
  if (!mediaPath) throw new Error('YouTube requires a video file');

  // Step 1: Get a fresh access token using the refresh token
  const tokenRes = await axios.post('https://oauth2.googleapis.com/token', {
    client_id: clientId,
    client_secret: clientSecret,
    refresh_token: refreshToken,
    grant_type: 'refresh_token',
  });
  const accessToken = tokenRes.data.access_token;

  // Step 2: Upload the video
  const fileStream = fs.createReadStream(mediaPath);
  const fileSize   = fs.statSync(mediaPath).size;

  const uploadRes = await axios.post(
    'https://www.googleapis.com/upload/youtube/v3/videos?uploadType=resumable&part=snippet,status',
    {
      snippet: {
        title: text.substring(0, 100),
        description: text,
        categoryId: '22', // People & Blogs
      },
      status: { privacyStatus: 'public' },
    },
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        'X-Upload-Content-Type': 'video/mp4',
        'X-Upload-Content-Length': fileSize,
      },
    }
  );

  const resumableUri = uploadRes.headers.location;

  // Step 3: Send the actual video bytes
  const videoRes = await axios.put(resumableUri, fileStream, {
    headers: {
      'Content-Type': 'video/mp4',
      'Content-Length': fileSize,
      Authorization: `Bearer ${accessToken}`,
    },
    maxBodyLength: Infinity,
    maxContentLength: Infinity,
  });

  return { id: videoRes.data.id, url: `https://youtu.be/${videoRes.data.id}` };
}

// ════════════════════════════════════════════════════════════════
//  CRON — Process scheduled posts every minute
// ════════════════════════════════════════════════════════════════
cron.schedule('* * * * *', async () => {
  const now = new Date();
  const due = scheduledPosts.filter(
    j => j.status === 'pending' && new Date(j.scheduledAt) <= now
  );

  for (const job of due) {
    console.log(`[CRON] Running scheduled post id=${job.id} for: ${job.platforms.join(', ')}`);
    job.status = 'running';

    try {
      const results = {};
      const errors  = {};

      await Promise.allSettled(
        job.platforms.map(async (platform) => {
          try {
            switch (platform) {
              case 'Facebook':  results.Facebook  = await postToFacebook(job.text, null); break;
              case 'Instagram': results.Instagram = await postToInstagram(job.text, null); break;
              case 'X':         results.X         = await postToX(job.text, null); break;
              case 'TikTok':    results.TikTok    = await postToTikTok(job.text, null); break;
              case 'YouTube':   results.YouTube   = await postToYouTube(job.text, null); break;
            }
          } catch (e) {
            errors[platform] = e.message;
          }
        })
      );

      job.status  = 'done';
      job.results = results;
      job.errors  = errors;
      console.log(`[CRON] Done — posted: ${Object.keys(results).join(', ')}`);
    } catch (e) {
      job.status = 'failed';
      job.error  = e.message;
      console.error(`[CRON] Failed: ${e.message}`);
    }
  }
});

// ── HEALTH CHECK ──────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    app: 'MFM YC SocialHub',
    time: new Date().toISOString(),
    platforms: {
      facebook:  !!process.env.FB_PAGE_ACCESS_TOKEN,
      instagram: !!process.env.IG_BUSINESS_ACCOUNT_ID,
      x:         !!process.env.X_BEARER_TOKEN,
      tiktok:    !!process.env.TIKTOK_ACCESS_TOKEN,
      youtube:   !!process.env.YOUTUBE_REFRESH_TOKEN,
    },
  });
});

// ── START ─────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🔥 MFM YC SocialHub backend running on port ${PORT}`);
  console.log(`   Health check: http://localhost:${PORT}/api/health\n`);
});
