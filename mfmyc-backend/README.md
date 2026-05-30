# MFM YC SocialHub — Backend

## Quick Deploy to Railway

1. Push this folder to a GitHub repo
2. Go to railway.app → New Project → Deploy from GitHub
3. Select your repo
4. Go to Variables tab → add all keys from .env.example
5. Railway auto-deploys. Copy your Railway URL e.g. https://mfmyc-backend.up.railway.app

## Local Development

```bash
npm install
cp .env.example .env
# Fill in .env with your keys
npm run dev
```

## API Endpoints

| Method | Route | Auth | Description |
|--------|-------|------|-------------|
| POST | /api/auth/login | None | Login, returns JWT token |
| GET | /api/auth/me | JWT | Get current user |
| POST | /api/ai/caption | JWT | Generate AI caption |
| POST | /api/post | JWT | Post to platforms |
| POST | /api/schedule | JWT | Schedule a post |
| GET | /api/schedule | JWT | List scheduled posts |
| DELETE | /api/schedule/:id | JWT | Remove scheduled post |
| GET | /api/admins | JWT+Owner | List all admins |
| POST | /api/admins | JWT+Owner | Add an admin |
| DELETE | /api/admins/:username | JWT+Owner | Remove an admin |
| GET | /api/health | None | Server + platform status |

## Getting API Keys

### Facebook & Instagram
1. Go to developers.facebook.com
2. Create App → Business type
3. Add "Pages API" and "Instagram Graph API"
4. Generate a Page Access Token (never expires if set to long-lived)
5. Copy FB_PAGE_ID, FB_APP_ID, FB_APP_SECRET, FB_PAGE_ACCESS_TOKEN
6. Copy IG_BUSINESS_ACCOUNT_ID from Instagram account settings

### X (Twitter)
1. Go to developer.twitter.com
2. Create a project + app (Basic plan ~$100/month for write access)
3. Under Keys and Tokens: copy all 5 values

### TikTok
1. Go to developers.tiktok.com
2. Create app, request "Content Posting API" access
3. Generate access token via OAuth flow

### YouTube
1. Go to console.cloud.google.com
2. Create project → Enable YouTube Data API v3
3. Create OAuth 2.0 credentials
4. Run the OAuth flow once to get your refresh token
5. Copy YOUTUBE_CLIENT_ID, YOUTUBE_CLIENT_SECRET, YOUTUBE_REFRESH_TOKEN
