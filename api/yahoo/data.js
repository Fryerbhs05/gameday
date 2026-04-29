// api/yahoo/data.js
// Authenticated proxy to the Yahoo Fantasy Sports API. Reads the encrypted
// session cookie, transparently refreshes the access token when expired,
// and calls the requested Yahoo endpoint on the user's behalf.
//
// Usage from the frontend:
//   fetch('/api/yahoo/data?endpoint=leagues')
//   fetch('/api/yahoo/data?endpoint=standings&league_key=nfl.l.12345')
//   fetch('/api/yahoo/data?endpoint=scoreboard&league_key=nfl.l.12345')
//   fetch('/api/yahoo/data?endpoint=roster&team_key=nfl.l.12345.t.6')

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

function decrypt(sealed) {
  const buf = Buffer.from(sealed, 'base64url');
  const iv = buf.slice(0, 12);
  const tag = buf.slice(12, 28);
  const data = buf.slice(28);
  const decipher = crypto.createDecipheriv(ALGO, getKey(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
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

async function refreshAccessToken(refreshTok) {
  const clientId = process.env.YAHOO_CLIENT_ID;
  const clientSecret = process.env.YAHOO_CLIENT_SECRET;
  const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

  const r = await fetch('https://api.login.yahoo.com/oauth2/get_token', {
    method: 'POST',
    headers: {
      Authorization: `Basic ${basicAuth}`,
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshTok,
      redirect_uri: process.env.YAHOO_REDIRECT_URI
    }).toString()
  });

  if (!r.ok) throw new Error(`Refresh failed: ${await r.text()}`);
  return await r.json();
}

module.exports = async (req, res) => {
  try {
    const cookies = parseCookies(req);
    if (!cookies.yahoo_session) {
      res
        .status(401)
        .json({ error: 'Not authenticated. Visit /api/auth/yahoo to log in.' });
      return;
    }

    let session;
    try {
      session = JSON.parse(decrypt(cookies.yahoo_session));
    } catch (e) {
      res.status(401).json({ error: 'Invalid session' });
      return;
    }

    let accessToken = session.at;

    // Refresh with 60s buffer before expiry
    if (Math.floor(Date.now() / 1000) >= session.exp - 60) {
      try {
        const fresh = await refreshAccessToken(session.rt);
        accessToken = fresh.access_token;
        const newSession = {
          at: fresh.access_token,
          rt: fresh.refresh_token || session.rt,
          exp: Math.floor(Date.now() / 1000) + (fresh.expires_in || 3600),
          guid: session.guid
        };
        const sealed = encrypt(JSON.stringify(newSession));
        res.setHeader(
          'Set-Cookie',
          `yahoo_session=${sealed}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`
        );
      } catch (e) {
        res.status(401).json({ error: 'Session expired, please log in again' });
        return;
      }
    }

    // Pick the Yahoo endpoint to hit
    const endpoint = (req.query.endpoint || 'leagues').toString();
    let url;
    if (endpoint === 'leagues') {
      url =
        'https://fantasysports.yahooapis.com/fantasy/v2/users;use_login=1/games;game_keys=nfl/leagues?format=json';
    } else if (endpoint === 'standings' && req.query.league_key) {
      url = `https://fantasysports.yahooapis.com/fantasy/v2/league/${encodeURIComponent(
        req.query.league_key
      )}/standings?format=json`;
    } else if (endpoint === 'scoreboard' && req.query.league_key) {
      url = `https://fantasysports.yahooapis.com/fantasy/v2/league/${encodeURIComponent(
        req.query.league_key
      )}/scoreboard?format=json`;
    } else if (endpoint === 'roster' && req.query.team_key) {
      url = `https://fantasysports.yahooapis.com/fantasy/v2/team/${encodeURIComponent(
        req.query.team_key
      )}/roster?format=json`;
    } else {
      res.status(400).json({ error: 'Unknown endpoint or missing parameters' });
      return;
    }

    const yRes = await fetch(url, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    if (!yRes.ok) {
      const txt = await yRes.text();
      res.status(yRes.status).json({ error: 'Yahoo API error', detail: txt });
      return;
    }

    const data = await yRes.json();
    res.status(200).json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};
