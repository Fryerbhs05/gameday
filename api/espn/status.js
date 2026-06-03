// api/espn/status.js
// Lightweight "are we connected?" probe the frontend hits on bootstrap.
// When connected, also returns the user's SWID + league_id so the frontend
// can identify "my team" in ESPN's response (where teams are owned by SWID).
// SWID alone isn't an auth secret — it's just an identifier — so exposing
// it to JS is safe; espn_s2 stays sealed in the encrypted session cookie.

const crypto = require('crypto');

// Optional accounts layer — inert unless Supabase env vars are configured.
let A = null;
try { A = require('../_lib/accounts'); } catch (e) { A = null; }

const ALGO = 'aes-256-gcm';

function getKey() {
  const secret = process.env.SESSION_SECRET;
  if (!secret) throw new Error('SESSION_SECRET not set');
  return crypto.createHash('sha256').update(secret).digest();
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

module.exports = async (req, res) => {
  const cookies = parseCookies(req);

  // Cookie first (today's path), then the account-stored blob as a fallback so
  // a signed-in user shows "connected" on a device that never pasted cookies.
  let sealed = cookies.espn_session || null;
  const fromCookie = !!sealed;
  let viaAccount = false;

  // Resolve the signed-in account once (if any) — used for both fallback and
  // auto-migration below.
  let acct = null;
  if (A && A.accountsConfigured()) {
    try { acct = A.readAccount(req); } catch (e) { acct = null; }
  }

  if (!sealed && acct) {
    try {
      sealed = await A.getPlatformSession(acct.uid, 'espn');
      if (sealed) viaAccount = true;
    } catch (e) {
      console.error('espn/status account lookup failed (non-fatal):', e.message);
    }
  }

  // Auto-migrate: a signed-in user whose ESPN is connected in THIS browser
  // (cookie) gets that session mirrored into their account, so it follows them
  // to other devices with no cookie re-paste. Idempotent upsert, best-effort —
  // this is what makes a pre-existing desktop connection "just appear" on mobile
  // the moment the user signs in on desktop and loads the app.
  if (fromCookie && acct) {
    try {
      await A.savePlatformSession(acct.uid, 'espn', sealed);
    } catch (e) {
      console.error('espn/status account auto-migrate failed (non-fatal):', e.message);
    }
  }

  if (!sealed) {
    res.status(200).json({ connected: false });
    return;
  }
  try {
    const session = JSON.parse(decrypt(sealed));
    const league_ids = Array.isArray(session.lids) && session.lids.length
      ? session.lids.map(String)
      : (session.lid ? [String(session.lid)] : []);
    res.status(200).json({
      connected: true,
      swid: session.sw,
      league_id: league_ids[0] || null,   // legacy single-id field
      league_ids,                          // full set
      league_names: session.lnames || {},  // id -> display name (best-effort)
      league_count: league_ids.length,
      viaAccount
    });
  } catch (e) {
    // Bad/old session — treat as disconnected
    res.status(200).json({ connected: false });
  }
};
