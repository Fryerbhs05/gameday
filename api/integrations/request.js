// api/integrations/request.js
// Captures forward-looking demand from the connect wizard's "Don't see your
// platform?" prompt. The user can check MULTIPLE platforms; the picks ride along
// with the wizard's Continue click (no dedicated submit button).
//
//   POST /api/integrations/request
//     { platforms: ["cbs","nfl"], notify: true, source: "wizard" }
//
// `notify` means "email me when ready" — we use the SIGNED-IN ACCOUNT'S email
// (collected at sign-up), never a separately typed address. A single `platform`
// string and an explicit `email` are still accepted for backward-compat.
//
// Design notes:
//   • Inert without Supabase: if accounts aren't configured we still answer 200
//     so the wizard proceeds. Nothing is stored, nothing breaks.
//   • Best-effort, fail-soft: this is a non-critical signal. We never want a
//     capture hiccup to surface an error in the connect flow, so even a storage
//     failure returns ok:true (the helper logs server-side).
//   • Rate-limited per IP to keep the table from being spammed. Fails open.
//   • Attaches the signed-in user_id when present (anonymous asks are fine too).

const A = require('../_lib/accounts');

async function readJsonBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') {
    try { return JSON.parse(req.body); } catch { return {}; }
  }
  return await new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch { resolve({}); } });
    req.on('error', () => resolve({}));
  });
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }
  try {
    const body = await readJsonBody(req);
    // Accept an array of platforms, or a single `platform` (backward-compat).
    const rawList = Array.isArray(body.platforms)
      ? body.platforms
      : (body.platform ? [body.platform] : []);
    const platforms = [];
    for (const p of rawList) {
      const s = String(p || '').trim().slice(0, 80);
      if (s && !platforms.includes(s)) platforms.push(s);
    }
    if (!platforms.length) {
      res.status(400).json({ error: 'platform(s) required' });
      return;
    }
    if (platforms.length > 12) platforms.length = 12; // sanity cap

    // Per-IP throttle (fails open — see A.rateLimitOk). Generous: this is a
    // single deliberate click, not a hot path.
    const ip = A.clientIp(req);
    if (!(await A.rateLimitOk(`intreq:ip:${ip}`, 30, 3600))) {
      res.status(429).json({ error: 'Too many requests. Please try again later.' });
      return;
    }

    // Anonymous is fine; attach the account when the user is signed in.
    let userId = null;
    let acctEmail = null;
    try {
      const acct = A.readAccount(req);
      if (acct) { userId = acct.uid; acctEmail = acct.email || null; }
    } catch (e) { /* ignore */ }

    // `notify` opts into the waitlist using the account email. An explicitly
    // posted, valid email is honored too (legacy path).
    const notify = body.notify === true || body.notify === 'true';
    let email = null;
    if (notify && acctEmail) email = acctEmail;
    else if (body.email && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(String(body.email).trim())) {
      email = String(body.email).trim();
    }

    const source = body.source ? String(body.source).trim().slice(0, 40) : 'wizard';
    // One row per platform; same email/user attached to each.
    await Promise.all(
      platforms.map((platform) =>
        A.saveIntegrationRequest({ platform, email, source, userId })
      )
    );

    // Always 200 — stored or not, the wizard should proceed cleanly.
    res.status(200).json({ ok: true });
  } catch (e) {
    console.error('integrations/request error (non-fatal):', e.message);
    // Even on an unexpected error we don't want the wizard to show a failure for
    // a non-critical signal capture.
    res.status(200).json({ ok: true });
  }
};

// Error monitoring: re-wrap the handler so any uncaught throw is reported
// to Sentry (inert until SENTRY_DSN is set). See api/_lib/observe.js.
module.exports = require('../_lib/observe').wrap(module.exports, 'integrations:request');
