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

    // Wizard (new-tab) mode: the ".w" marker on the state means this tab was
    // opened by the connect wizard. Show a small branded confirmation that closes
    // itself, instead of reloading the whole app here. The wizard tab detects the
    // connection by polling and advances on its own.
    if (typeof state === 'string' && state.endsWith('.w')) {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Cache-Control', 'no-store');
      res.status(200).send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Yahoo connected</title>
<style>
  html,body{height:100%;margin:0}
  body{display:flex;align-items:center;justify-content:center;background:#0F1B26;color:#F5EFE1;font-family:-apple-system,Segoe UI,Roboto,sans-serif}
  .box{text-align:center;max-width:340px;padding:28px}
  .check{width:56px;height:56px;border-radius:50%;background:#2E7D5B;display:flex;align-items:center;justify-content:center;margin:0 auto 16px;font-size:30px;color:#fff}
  h1{font-size:20px;margin:0 0 8px}
  p{font-size:14px;line-height:1.5;color:#C9C2B2;margin:0 0 18px}
  button{background:#FF6B5A;color:#1a1208;border:0;border-radius:8px;padding:11px 20px;font-weight:600;font-size:14px;cursor:pointer}
</style></head><body>
  <div class="box">
    <div class="check">&#10003;</div>
    <h1>Yahoo connected</h1>
    <p>You're all set. You can close this tab and return to Conflicted &mdash; it picks up automatically.</p>
    <button onclick="window.close()">Close this tab</button>
  </div>
  <script>setTimeout(function(){try{window.close();}catch(e){}},1200);</script>
</body></html>`);
      return;
    }

    res.writeHead(302, { Location: '/?yahoo=connected' });
    res.end();
  } catch (e) {
    res.status(500).send(`Callback error: ${e.message}`);
  }
};
