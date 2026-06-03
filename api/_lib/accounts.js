// api/_lib/accounts.js
// Shared helpers for the lightweight accounts system (magic-link auth +
// account-keyed, server-side platform-session storage).
//
// Design goals that make this safe to deploy BEFORE it's configured:
//   • Zero npm dependencies — Supabase and Resend are both called over plain
//     HTTPS with the built-in global `fetch`, matching the existing api/*
//     functions (which only use `crypto`). No package.json change needed.
//   • Fully inert without env vars. If SUPABASE_URL / SUPABASE_SERVICE_KEY
//     aren't set, accountsConfigured() is false and every caller no-ops or
//     returns a clean 503. Uploading these files will NOT change the live
//     site's behavior until you flip the env vars on.
//   • Reuses the same AES-256-GCM scheme + SESSION_SECRET as the Yahoo/ESPN
//     cookies, so encrypted blobs are interchangeable.
//
// Required env vars to activate (see ACCOUNTS-SETUP.md):
//   SESSION_SECRET        — already set today (reused for encryption)
//   SUPABASE_URL          — e.g. https://abcd1234.supabase.co
//   SUPABASE_SERVICE_KEY  — Supabase "service_role" key (server-only, secret)
//   RESEND_API_KEY        — Resend API key for sending magic-link emails
//   APP_URL               — e.g. https://conflicted-fantasy.vercel.app
//   MAGIC_FROM            — optional; from-address, defaults below

const crypto = require('crypto');

const ALGO = 'aes-256-gcm';

/* ── Config ─────────────────────────────────────────────────────── */
function accountsConfigured() {
  return Boolean(
    process.env.SESSION_SECRET &&
      process.env.SUPABASE_URL &&
      process.env.SUPABASE_SERVICE_KEY
  );
}
function emailConfigured() {
  return Boolean(process.env.RESEND_API_KEY);
}
function appUrl() {
  return (process.env.APP_URL || 'https://conflicted-fantasy.vercel.app').replace(/\/$/, '');
}

/* ── Crypto (identical scheme to api/auth/callback.js) ──────────── */
function getKey() {
  const secret = process.env.SESSION_SECRET;
  if (!secret) throw new Error('SESSION_SECRET not set');
  return crypto.createHash('sha256').update(secret).digest();
}
function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO, getKey(), iv);
  const enc = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString('base64url');
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

/* ── Cookies ────────────────────────────────────────────────────── */
function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach((c) => {
    const i = c.indexOf('=');
    if (i > -1) out[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim());
  });
  return out;
}

// The logged-in account cookie. 30-day, HttpOnly, encrypted { uid, email, exp }.
function makeAccountCookie(uid, email) {
  const payload = JSON.stringify({
    uid,
    email,
    exp: Math.floor(Date.now() / 1000) + 2592000
  });
  const sealed = encrypt(payload);
  return `account_session=${sealed}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`;
}
function clearAccountCookie() {
  return `account_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}
// Returns { uid, email } or null. Safe to call anywhere; never throws.
function readAccount(req) {
  try {
    const cookies = parseCookies(req);
    if (!cookies.account_session) return null;
    const a = JSON.parse(decrypt(cookies.account_session));
    if (!a || !a.uid || (a.exp && Math.floor(Date.now() / 1000) > a.exp)) return null;
    return { uid: a.uid, email: a.email };
  } catch (e) {
    return null;
  }
}

/* ── Supabase REST (PostgREST) ──────────────────────────────────── */
// We use the service_role key from a server function only — never exposed to
// the browser — so row-level security is bypassed intentionally and the
// schema can keep RLS on to block any anon/public access.
async function sbFetch(path, opts = {}) {
  const base = process.env.SUPABASE_URL.replace(/\/$/, '');
  const key = process.env.SUPABASE_SERVICE_KEY;
  // Key-format handling — this matters:
  //   • Legacy keys (anon / service_role) ARE JWTs (start with "eyJ"). PostgREST
  //     reads the role from the JWT in the Authorization: Bearer header, so we
  //     must send it there.
  //   • New keys (sb_secret_ / sb_publishable_) are NOT JWTs. If we send one as
  //     a Bearer token, PostgREST tries to verify it as a JWT, fails, and rejects
  //     the request. For these we pass the key ONLY in the apikey header and let
  //     Supabase's gateway map it to the right role.
  const isJwt = /^eyJ/.test(key || '');
  const headers = {
    apikey: key,
    'Content-Type': 'application/json',
    ...(opts.headers || {})
  };
  if (isJwt) headers.Authorization = `Bearer ${key}`;
  const r = await fetch(`${base}/rest/v1/${path}`, {
    ...opts,
    headers
  });
  if (!r.ok) {
    const txt = await r.text().catch(() => '');
    throw new Error(`Supabase ${r.status}: ${txt.slice(0, 300)}`);
  }
  // Some writes return no body (Prefer: return=minimal)
  const text = await r.text();
  return text ? JSON.parse(text) : null;
}

function normEmail(email) {
  return String(email || '').trim().toLowerCase();
}

// Create the user if missing, return the row { id, email }.
async function upsertUser(email) {
  const e = normEmail(email);
  const rows = await sbFetch('users', {
    method: 'POST',
    headers: {
      Prefer: 'resolution=merge-duplicates,return=representation'
    },
    body: JSON.stringify([{ email: e }])
  });
  if (rows && rows[0]) return rows[0];
  // merge-duplicates with return=minimal can yield null — fetch it back.
  const found = await sbFetch(`users?email=eq.${encodeURIComponent(e)}&select=id,email`);
  return found && found[0];
}

/* ── Magic tokens ───────────────────────────────────────────────── */
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}
// Store only the HASH of the token; the raw token lives only in the emailed URL.
async function saveMagicToken(email, ttlMinutes = 15) {
  const token = crypto.randomBytes(32).toString('base64url');
  const token_hash = hashToken(token);
  const expires_at = new Date(Date.now() + ttlMinutes * 60000).toISOString();
  await sbFetch('magic_tokens', {
    method: 'POST',
    headers: { Prefer: 'return=minimal' },
    body: JSON.stringify([{ token_hash, email: normEmail(email), expires_at }])
  });
  return token;
}
// Verify + single-use consume. Returns the email if valid, else null.
async function consumeMagicToken(token) {
  if (!token) return null;
  const token_hash = hashToken(token);
  const rows = await sbFetch(
    `magic_tokens?token_hash=eq.${token_hash}&select=email,expires_at`
  );
  const row = rows && rows[0];
  if (!row) return null;
  // Always delete (single use), regardless of expiry outcome.
  await sbFetch(`magic_tokens?token_hash=eq.${token_hash}`, {
    method: 'DELETE',
    headers: { Prefer: 'return=minimal' }
  }).catch(() => {});
  if (new Date(row.expires_at).getTime() < Date.now()) return null;
  return row.email;
}

/* ── Platform sessions (account-keyed ESPN / Yahoo blobs) ───────── */
// blob = the SAME base64url ciphertext we'd otherwise put in the cookie.
async function savePlatformSession(uid, platform, blob) {
  await sbFetch('platform_sessions', {
    method: 'POST',
    headers: { Prefer: 'resolution=merge-duplicates,return=minimal' },
    body: JSON.stringify([
      { user_id: uid, platform, blob, updated_at: new Date().toISOString() }
    ])
  });
}
async function getPlatformSession(uid, platform) {
  const rows = await sbFetch(
    `platform_sessions?user_id=eq.${uid}&platform=eq.${platform}&select=blob`
  );
  return rows && rows[0] ? rows[0].blob : null;
}
async function deletePlatformSession(uid, platform) {
  await sbFetch(
    `platform_sessions?user_id=eq.${uid}&platform=eq.${platform}`,
    { method: 'DELETE', headers: { Prefer: 'return=minimal' } }
  );
}
// Full account erasure (GDPR/CCPA "delete my data").
async function deleteUserData(uid, email) {
  await sbFetch(`platform_sessions?user_id=eq.${uid}`, {
    method: 'DELETE',
    headers: { Prefer: 'return=minimal' }
  }).catch(() => {});
  if (email) {
    await sbFetch(`magic_tokens?email=eq.${encodeURIComponent(normEmail(email))}`, {
      method: 'DELETE',
      headers: { Prefer: 'return=minimal' }
    }).catch(() => {});
  }
  await sbFetch(`users?id=eq.${uid}`, {
    method: 'DELETE',
    headers: { Prefer: 'return=minimal' }
  });
}

/* ── Email (Resend REST) ────────────────────────────────────────── */
async function sendMagicLink(email, token) {
  // Verification is handled by the GET branch of /api/auth/magic/request
  // (consolidated into one function to stay under Vercel Hobby's 12-fn limit).
  const link = `${appUrl()}/api/auth/magic/request?token=${encodeURIComponent(token)}`;
  const from = process.env.MAGIC_FROM || 'Conflicted <login@conflicted-fantasy.vercel.app>';
  const html = `
    <div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:480px;margin:0 auto;padding:24px;color:#1a2233">
      <h2 style="margin:0 0 8px">Sign in to Conflicted</h2>
      <p style="color:#5a6472;font-size:14px;line-height:1.5">Tap the button below to finish signing in. This link works once and expires in 15 minutes.</p>
      <p style="margin:24px 0">
        <a href="${link}" style="background:#1b2a4a;color:#fff;text-decoration:none;padding:12px 22px;border-radius:8px;font-weight:600;font-size:14px;display:inline-block">Sign in to Conflicted</a>
      </p>
      <p style="color:#8a93a3;font-size:12px;line-height:1.5">If you didn't request this, you can ignore this email — nothing will happen.</p>
    </div>`;
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from,
      to: [normEmail(email)],
      subject: 'Your Conflicted sign-in link',
      html
    })
  });
  if (!r.ok) {
    const txt = await r.text().catch(() => '');
    throw new Error(`Resend ${r.status}: ${txt.slice(0, 300)}`);
  }
  return true;
}

module.exports = {
  accountsConfigured,
  emailConfigured,
  appUrl,
  encrypt,
  decrypt,
  parseCookies,
  makeAccountCookie,
  clearAccountCookie,
  readAccount,
  normEmail,
  upsertUser,
  saveMagicToken,
  consumeMagicToken,
  savePlatformSession,
  getPlatformSession,
  deletePlatformSession,
  deleteUserData,
  sendMagicLink
};
