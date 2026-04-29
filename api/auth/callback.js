// api/auth/callback.js
// Yahoo redirects here after the user approves. We verify the state,
// exchange the authorization code for access + refresh tokens, encrypt
// them into an HttpOnly cookie, and bounce the user back to the app.

const crypto = require('crypto');

const ALGO = 'aes-256-gcm';

function getKey() {
  const secret = process.env.SESSION_SECRET;
  if (!secret) throw new Error('SESSION_SECRET not set');
  return crypto.createHash('sha256').update(secret).digest();
}

function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO, getKey(), iv);
  const encrypted = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64url');
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach((c) => {
    const i = c.indexOf('=');
    if (i > -1) {
      out[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim());
    }
  });
  return out;
}

module.exports = async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) {
      res.status(400).send(`Yahoo OAuth error: ${error}`);
      return;
    }
    if (!code) {
      res.status(400).send('Missing authorization code');
      return;
    }

    // CSRF: state from cookie must match state Yahoo sent back
    const cookies = parseCookies(req);
    if (!cookies.yahoo_oauth_state || cookies.yahoo_oauth_state !== state) {
      res
        .status(400)
        .send('Invalid state — possible CSRF attempt. Please try logging in again.');
      return;
    }

    const clientId = process.env.YAHOO_CLIENT_ID;
    const clientSecret = process.env.YAHOO_CLIENT_SECRET;
    const redirectUri = process.env.YAHOO_REDIRECT_URI;

    const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

    const tokenRes = await fetch('https://api.login.yahoo.com/oauth2/get_token', {
      method: 'POST',
      headers: {
        Authorization: `Basic ${basicAuth}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: redirectUri
      }).toString()
    });

    if (!tokenRes.ok) {
      const txt = await tokenRes.text();
      res.status(500).send(`Token exchange failed: ${txt}`);
      return;
    }

    const tokens = await tokenRes.json();
    // tokens: { access_token, refresh_token, expires_in, token_type, xoauth_yahoo_guid }

    const session = JSON.stringify({
      at: tokens.access_token,
      rt: tokens.refresh_token,
      exp: Math.floor(Date.now() / 1000) + (tokens.expires_in || 3600),
      guid: tokens.xoauth_yahoo_guid
    });

    const sealed = encrypt(session);

    res.setHeader('Set-Cookie', [
      // 30-day session cookie, HttpOnly so JavaScript can't read it
      `yahoo_session=${sealed}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`,
      // clear the state cookie
      `yahoo_oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
    ]);

    res.writeHead(302, { Location: '/?yahoo=connected' });
    res.end();
  } catch (e) {
    res.status(500).send(`Callback error: ${e.message}`);
  }
};
