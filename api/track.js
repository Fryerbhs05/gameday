// api/track.js
// Analytics ingestion. (Written under the old Hobby 12-function cap; the
// project is on Pro now, so that cap no longer applies.) One endpoint, batched
// events, zero npm dependencies, matching the api/* house style.
//
//   POST /api/track
//   body: { anon_id, events: [{ name, props }] }   (or a single { name, props })
//
// Design rules (all deliberate):
//   • INERT without env vars — if Supabase isn't configured, respond 204 and
//     do nothing. Uploading this file cannot change live behavior until the
//     existing SUPABASE_* env vars are present (they already are in prod).
//   • NEVER an error the client sees — analytics must never break or slow the
//     app. Every failure path still returns 204. Failures go to Sentry via
//     observe.js so we know, but the user never does.
//   • sendBeacon-friendly — navigator.sendBeacon posts text/plain; we parse
//     the raw body regardless of Content-Type.
//   • Validated + capped — event names must match ^[a-z][a-z0-9_]{0,49}$,
//     max 20 events per call, props capped at 2 KB per event, anon_id at 64
//     chars. Junk is dropped silently, not rejected.
//   • Rate-limited per IP (120 calls/min) through the existing Postgres-backed
//     limiter; over-limit calls are dropped (204), never blocked with an error.
//   • Signed-in calls also touch users.last_seen_at — the cheap retention
//     signal ("active in last N days") without scanning events.
//   • ip_hash (added 2026-10-12): every row carries a keyed hash of the
//     caller's network so the owner's private-window test sessions can be
//     filtered out of anonymous counts (match against the owner's signed-in
//     rows from the same network). The raw IP is NEVER stored. IPv6 is cut to
//     its /64 prefix first, because phones rotate the lower 64 bits for
//     privacy and the /64 is what identifies one home/LAN. Key = IP_HASH_SALT,
//     falling back to SESSION_SECRET; with neither set the column stays null.

const crypto = require('crypto');
const A = require('./_lib/accounts');
const O = require('./_lib/observe');

// Network key for one caller: full IPv4, or the /64 prefix of an IPv6 address.
function networkKey(ip) {
  if (!ip || ip === 'unknown') return null;
  let s = String(ip).trim().toLowerCase();
  if (s.startsWith('::ffff:') && s.indexOf('.') > 0) s = s.slice(7);   // IPv4-mapped IPv6
  if (s.indexOf(':') === -1) return /^\d{1,3}(\.\d{1,3}){3}$/.test(s) ? s : null;
  s = s.split('%')[0];                                                // drop zone id
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length === 2 ? Math.max(0, 8 - head.length - tail.length) : 0;
  const groups = head.concat(new Array(fill).fill('0'), tail);
  if (groups.length < 4) return null;
  return groups.slice(0, 4).map((g) => (parseInt(g || '0', 16) || 0).toString(16)).join(':') + '::/64';
}

// Keyed so a leaked events table can't be reversed by hashing all 4B IPv4s.
function ipHash(req) {
  try {
    const key = process.env.IP_HASH_SALT || process.env.SESSION_SECRET;
    const net = networkKey(A.clientIp(req));
    if (!key || !net) return null;
    return crypto.createHmac('sha256', key).update('cf-ip:' + net).digest('hex').slice(0, 16);
  } catch (e) { return null; }
}

const NAME_RE = /^[a-z][a-z0-9_]{0,49}$/;
const MAX_EVENTS = 20;
const MAX_PROPS_BYTES = 2048;

// Same tolerant body reader as api/account/me.js, but Content-Type-agnostic
// because sendBeacon sends text/plain.
async function readJsonBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') {
    try { return JSON.parse(req.body); } catch (e) { return {}; }
  }
  return await new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => { data += c; if (data.length > 65536) req.destroy(); });
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch (e) { resolve({}); } });
    req.on('error', () => resolve({}));
  });
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') { res.status(405).json({ error: 'POST only' }); return; }
  if (!A.accountsConfigured()) { res.status(204).end(); return; }

  try {
    // Over-limit → drop silently. An abusive client learns nothing; a burst of
    // legit traffic loses a few events, which is acceptable for analytics.
    const allowed = await A.rateLimitOk(`track:${A.clientIp(req)}`, 120, 60);
    if (!allowed) { res.status(204).end(); return; }

    const body = await readJsonBody(req);
    const anonId = typeof body.anon_id === 'string' ? body.anon_id.slice(0, 64) : null;
    let list = Array.isArray(body.events) ? body.events : (body && body.name ? [body] : []);
    list = list.slice(0, MAX_EVENTS);

    const acct = A.readAccount(req); // { uid, email } or null — never throws
    const ipH = ipHash(req);
    const rows = [];
    for (const ev of list) {
      if (!ev || typeof ev.name !== 'string' || !NAME_RE.test(ev.name)) continue;
      let props = null;
      if (ev.props && typeof ev.props === 'object' && !Array.isArray(ev.props)) {
        try {
          const s = JSON.stringify(ev.props);
          if (s.length <= MAX_PROPS_BYTES) props = JSON.parse(s);
        } catch (e) { /* unserializable props → drop props, keep event */ }
      }
      rows.push({ user_id: acct ? acct.uid : null, anon_id: anonId, name: ev.name, props, ip_hash: ipH });
    }

    if (rows.length) {
      await A.sbFetch('events', {
        method: 'POST',
        headers: { Prefer: 'return=minimal' },
        body: JSON.stringify(rows)
      });
    }

    // Retention touch. Awaited (not fire-and-forget) because the serverless
    // runtime may freeze the instance the moment we respond.
    if (acct && rows.length) {
      try {
        await A.sbFetch(`users?id=eq.${encodeURIComponent(acct.uid)}`, {
          method: 'PATCH',
          headers: { Prefer: 'return=minimal' },
          body: JSON.stringify({ last_seen_at: new Date().toISOString() })
        });
      } catch (e) {
        O.reportError(e, { where: 'api/track:last_seen' });
      }
    }

    res.status(204).end();
  } catch (e) {
    try { O.reportError(e, { where: 'api/track' }); } catch (_) { /* noop */ }
    res.status(204).end(); // analytics failures are invisible by design
  }
};
