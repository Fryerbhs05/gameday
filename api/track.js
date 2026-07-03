// api/track.js
// Analytics ingestion — the 12th of 12 Vercel Hobby functions. WE ARE NOW AT
// THE CAP: any future endpoint MUST merge into an existing function via
// ?action= routing (see feedback_vercel_function_limit — over-limit deploys
// ERROR silently while serving the stale build). One endpoint, batched
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

const A = require('./_lib/accounts');
const O = require('./_lib/observe');

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
      rows.push({ user_id: acct ? acct.uid : null, anon_id: anonId, name: ev.name, props });
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
