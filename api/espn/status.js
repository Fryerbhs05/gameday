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
  let viaAccount = false;
  if (!sealed) {
    try {
      if (A && A.accountsConfigured()) {
        const acct = A.readAccount(req);
        if (acct) {
          sealed = await A.getPlatformSession(acct.uid, 'espn');
          if (sealed) viaAccount = true;
        }
      }
    } catch (e) {
      console.error('espn/status account lookup failed (non-fatal):', e.message);
    }
  }

  if (!sealed) {
    res.status(200).json({ connected: false });
    return;
  }
  try {
    const session = JSON.parse(decrypt(sealed));
    res.status(200).json({
      connected: true,
      swid: session.sw,
      league_id: session.lid,
      viaAccount
    });
  } catch (e) {
    // Bad/old session — treat as disconnected
    res.status(200).json({ connected: false });
  }
};
