// api/espn/save.js
// Accepts ESPN credentials (league_id, espn_s2, SWID) from the frontend,
// encrypts them with the same AES-256-GCM scheme as the Yahoo session,
// and stores them in an HttpOnly cookie.
//
// ESPN never built a public OAuth flow, so unlike Yahoo we can't use a
// redirect dance. Instead we accept the user's session cookies directly
// (they extract them from their own browser DevTools, or — eventually —
// via a browser extension / native WebView). Once stored here, the
// /api/espn/data.js proxy uses them to read the user's leagues.
//
// POST body (JSON): { league_id: "123456", espn_s2: "AEB...", swid: "{...}" }

const crypto = require('crypto');

// Optional accounts layer. require() is cheap and the helpers are inert unless
// the Supabase env vars are set, so this never affects the cookie-only path.
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

async function readJsonBody(req) {
  // Vercel's Node runtime sometimes pre-parses, sometimes not — handle both.
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') {
    try { return JSON.parse(req.body); } catch { return {}; }
  }
  return await new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => (data += chunk));
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); }
      catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

module.exports = async (req, res) => {
  try {
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      res.status(405).json({ error: 'Method not allowed' });
      return;
    }

    const body = await readJsonBody(req);
    let leagueId = String(body.league_id || '').trim();
    let espnS2 = String(body.espn_s2 || '').trim();
    let swid = String(body.swid || body.SWID || '').trim();

    // Server-side safety net mirroring the frontend smart-paste: if any field
    // arrives as a URL or a raw cookie blob (older client, or a paste that
    // slipped through validation), extract the real value here too.
    if (!/^[0-9]+$/.test(leagueId)) {
      const m = leagueId.match(/leagueId[=:]\s*(\d{2,})/i);
      if (m) leagueId = m[1];
    }
    if (/espn_s2/i.test(espnS2)) {
      const m = espnS2.match(/espn_s2\s*[=:]\s*["']?([^;\s"']+)/i);
      if (m) espnS2 = m[1];
    }
    if (/SWID/i.test(swid)) {
      const m = swid.match(/SWID\s*[=:]\s*["']?(\{?[0-9A-Fa-f-]{30,}\}?)/i);
      if (m) swid = m[1];
    }

    // Lightweight validation. Don't be paranoid — we're storing what the user
    // gave us; ESPN itself will reject bad cookies on the first data call.
    if (!leagueId || !/^[0-9]+$/.test(leagueId)) {
      res.status(400).json({ error: 'league_id is required and must be numeric' });
      return;
    }
    if (!espnS2 || espnS2.length < 50) {
      res.status(400).json({ error: 'espn_s2 looks too short — should be 100+ chars' });
      return;
    }
    if (!swid) {
      res.status(400).json({ error: 'SWID is required' });
      return;
    }
    // SWID is canonical with curly braces — add them if user stripped them.
    if (!swid.startsWith('{')) swid = `{${swid}`;
    if (!swid.endsWith('}')) swid = `${swid}}`;

    const session = JSON.stringify({
      lid: leagueId,
      s2: espnS2,
      sw: swid,
      // No expiry — espn_s2 rotates ~yearly and ESPN will 401 us when it does.
      // We'll detect that in /api/espn/data.js and surface a re-connect prompt.
      saved: Math.floor(Date.now() / 1000)
    });

    const sealed = encrypt(session);

    res.setHeader(
      'Set-Cookie',
      `espn_session=${sealed}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`
    );

    // Account layer (additive, best-effort): if the user is signed in to a
    // Conflicted account, ALSO stash this encrypted blob server-side keyed to
    // their account. That's what lets the same ESPN connection "just work" on
    // their phone later, without re-pasting cookies. Wrapped so any failure
    // (or no accounts configured) never affects the cookie flow above.
    let savedToAccount = false;
    try {
      if (A && A.accountsConfigured()) {
        const acct = A.readAccount(req);
        if (acct) {
          await A.savePlatformSession(acct.uid, 'espn', sealed);
          savedToAccount = true;
        }
      }
    } catch (e) {
      console.error('espn/save account store failed (non-fatal):', e.message);
    }

    res.status(200).json({ ok: true, league_id: leagueId, savedToAccount });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};
