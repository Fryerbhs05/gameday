// api/yahoo/data.js
// Authenticated proxy to the Yahoo Fantasy Sports API. Reads the encrypted
// session cookie, transparently refreshes the access token when expired,
// and calls the requested Yahoo endpoint on the user's behalf.
//
// Usage from the frontend:
//   fetch('/api/yahoo/data?endpoint=games')               // list every NFL season the user has leagues for
//   fetch('/api/yahoo/data?endpoint=leagues')             // current NFL season's leagues
//   fetch('/api/yahoo/data?endpoint=leagues&season=2025') // 2025 NFL season's leagues
//   fetch('/api/yahoo/data?endpoint=standings&league_key=nfl.l.12345')
//   fetch('/api/yahoo/data?endpoint=settings&league_key=nfl.l.12345')  // stat_modifiers → PPR/Half/Std
//   fetch('/api/yahoo/data?endpoint=scoreboard&league_key=nfl.l.12345&week=10')
//   fetch('/api/yahoo/data?endpoint=roster&team_key=nfl.l.12345.t.6&week=10')

const crypto = require('crypto');

// Account layer — inert without env vars, safe to import unconditionally.
let A = null;
try { A = require('../_lib/accounts'); } catch (e) { A = null; }

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

    // Resolve the signed-in account once (if any) — used for the abuse throttle
    // below, the read fallback, the self-heal write, and refresh writeback.
    let acct = null;
    try {
      if (A && A.accountsConfigured()) acct = A.readAccount(req);
    } catch (e) {
      console.error('yahoo/data account lookup failed (non-fatal):', e.message);
    }

    // ── Abuse throttle (fail-open — see api/_lib/accounts.rateLimitOk) ──────
    // This endpoint proxies to Yahoo on every call, so a runaway client or a
    // scraper could burn Vercel invocations and get our server IP rate-limited
    // by Yahoo. Cap requests per identity (signed-in account if present, else
    // client IP). The ceiling is generous — well above legit multi-league
    // polling — so only genuine abuse trips the 429. Runs before the token
    // refresh and the upstream fetch.
    if (A && A.accountsConfigured()) {
      try {
        const who = acct && acct.uid ? `acct:${acct.uid}` : `ip:${A.clientIp(req)}`;
        if (!(await A.rateLimitOk(`yahoo:data:${who}`, 100, 60))) {
          res.setHeader('Retry-After', '60');
          res.status(429).json({ error: 'Too many requests — please slow down and try again in a moment.' });
          return;
        }
      } catch (e) {
        console.error('yahoo/data throttle check failed (non-fatal):', e.message);
      }
    }

    // Prefer the per-browser cookie (today's path). If it's absent — e.g. the
    // user is on a different device where they never ran the OAuth flow — fall
    // back to the Yahoo blob stored against their signed-in account.
    let sealed = cookies.yahoo_session || null;
    const fromCookie = Boolean(sealed);
    if (!sealed && acct) {
      try { sealed = await A.getPlatformSession(acct.uid, 'yahoo'); }
      catch (e) { console.error('yahoo/data account session read failed (non-fatal):', e.message); }
    }

    if (!sealed) {
      res
        .status(401)
        .json({ error: 'Not authenticated. Visit /api/auth/yahoo to log in.' });
      return;
    }

    let session;
    try {
      session = JSON.parse(decrypt(sealed));
    } catch (e) {
      res.status(401).json({ error: 'Invalid session' });
      return;
    }

    // Self-heal: if this request authenticated from the cookie but the account
    // has no stored Yahoo blob yet (e.g. connected before account-sync shipped),
    // back-fill it now so the connection follows the user to other devices
    // without forcing a manual reconnect.
    if (fromCookie && acct) {
      try {
        const stored = await A.getPlatformSession(acct.uid, 'yahoo');
        if (!stored) await A.savePlatformSession(acct.uid, 'yahoo', sealed);
      } catch (e) {
        console.error('yahoo/data self-heal save failed (non-fatal):', e.message);
      }
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
        const resealed = encrypt(JSON.stringify(newSession));
        res.setHeader(
          'Set-Cookie',
          `yahoo_session=${resealed}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`
        );
        // Refresh writeback: persist the rotated token to the account too, or
        // the stored refresh token goes stale and cross-device access breaks.
        if (acct) {
          try { await A.savePlatformSession(acct.uid, 'yahoo', resealed); }
          catch (e) { console.error('yahoo/data refresh writeback failed (non-fatal):', e.message); }
        }
      } catch (e) {
        res.status(401).json({ error: 'Session expired, please log in again' });
        return;
      }
    }

    // Pick the Yahoo endpoint to hit
    const endpoint = (req.query.endpoint || 'leagues').toString();
    const season = req.query.season ? String(req.query.season).replace(/[^0-9]/g, '') : null;
    const week = req.query.week ? String(req.query.week).replace(/[^0-9]/g, '') : null;
    let url;

    if (endpoint === 'games') {
      // Lists every NFL game (season) the user has been part of — useful to
      // discover what years are available before drilling into leagues.
      url =
        'https://fantasysports.yahooapis.com/fantasy/v2/users;use_login=1/games;game_codes=nfl?format=json';
    } else if (endpoint === 'leagues') {
      // Current season by default. With ?season=YYYY, filter to that NFL season.
      // Yahoo accepts both `seasons=YYYY` (filter) and `game_keys=<id>` (specific game).
      const base = 'https://fantasysports.yahooapis.com/fantasy/v2/users;use_login=1/games';
      const filter = season ? `;game_codes=nfl;seasons=${season}` : ';game_keys=nfl';
      url = `${base}${filter}/leagues?format=json`;
    } else if (endpoint === 'standings' && req.query.league_key) {
      url = `https://fantasysports.yahooapis.com/fantasy/v2/league/${encodeURIComponent(
        req.query.league_key
      )}/standings?format=json`;
    } else if (endpoint === 'settings' && req.query.league_key) {
      // League settings — includes stat_modifiers, from which we derive the
      // real scoring format (PPR / Half / Std) via the receptions modifier.
      // Note: scoring_type on the league meta (head/points/roto) is the MATCHUP
      // type, not the scoring system, so it must be read from settings instead.
      url = `https://fantasysports.yahooapis.com/fantasy/v2/league/${encodeURIComponent(
        req.query.league_key
      )}/settings?format=json`;
    } else if (endpoint === 'scoreboard' && req.query.league_key) {
      const weekParam = week ? `;week=${week}` : '';
      url = `https://fantasysports.yahooapis.com/fantasy/v2/league/${encodeURIComponent(
        req.query.league_key
      )}/scoreboard${weekParam}?format=json`;
    } else if (endpoint === 'roster' && req.query.team_key) {
      const weekParam = week ? `;week=${week}` : '';
      url = `https://fantasysports.yahooapis.com/fantasy/v2/team/${encodeURIComponent(
        req.query.team_key
      )}/roster${weekParam}?format=json`;
    } else if (endpoint === 'roster_stats' && req.query.team_key) {
      // Roster + per-player stats (points) for a given week.
      // Yahoo composite resource: team/{key}/roster;week=N/players/stats;type=week;week=N
      // The roster's ;week=N selects which players were rostered that week.
      // The stats sub-resource needs its OWN ;type=week;week=N filter, otherwise
      // Yahoo defaults to the current period — which during off-season or for
      // historical seasons returns zero points across the board.
      const weekParam = week ? `;week=${week}` : '';
      const statsParam = week ? `;type=week;week=${week}` : '';
      url = `https://fantasysports.yahooapis.com/fantasy/v2/team/${encodeURIComponent(
        req.query.team_key
      )}/roster${weekParam}/players/stats${statsParam}?format=json`;
    } else {
      res.status(400).json({ error: 'Unknown endpoint or missing parameters' });
      return;
    }

    const yRes = await fetch(url, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    if (!yRes.ok) {
      const txt = await yRes.text();
      // TEMP DIAGNOSTIC: log Yahoo's verbatim rejection so it shows up in Vercel
      // runtime logs. Safe to remove once the Yahoo 403 is diagnosed.
      console.error(`YAHOO_DIAG ${yRes.status} endpoint=${endpoint} url=${url} body=${txt.slice(0, 800)}`);
      res.status(yRes.status).json({ error: 'Yahoo API error', detail: txt });
      return;
    }

    const data = await yRes.json();
    res.status(200).json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};

// Error monitoring: re-wrap the handler so any uncaught throw is reported
// to Sentry (inert until SENTRY_DSN is set). See api/_lib/observe.js.
module.exports = require('../_lib/observe').wrap(module.exports, 'yahoo:data');
