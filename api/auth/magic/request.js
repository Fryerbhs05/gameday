// api/auth/magic/request.js
// Combined magic-link endpoint (kept as ONE Vercel function to stay under the
// Hobby plan's 12-function limit):
//   POST /api/auth/magic/request               { email }                 -> mint token + email link
//   POST /api/auth/magic/request?mode=onboard  { email, first_name, last_name }
//                                                 -> create account + profile, sign in
//                                                    on THIS device (new/empty email), or
//                                                    email a link (existing email w/ data)
//   GET  /api/auth/magic/request?token=...      -> verify + sign in (the emailed link points here)
//
// The plain POST always responds 200 (no account enumeration). The onboarding
// POST intentionally distinguishes session-vs-link so the funnel can branch.

const A = require('../../_lib/accounts');
const O = require('../../_lib/observe');

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

// Throttle the email-sending paths. Returns true if the request may proceed,
// or false after writing a 429 (caller should just return). Two buckets:
//   • per-IP   — 20 / hour: stops one attacker spraying many addresses
//   • per-email — 4 / 15 min: stops bombing a single victim's inbox
// Both checks fail OPEN (A.rateLimitOk), so a limiter outage can't block logins.
// A 429 leaks no account info (it's about rate, not whether the email exists),
// so this preserves the endpoint's no-enumeration property.
async function rateLimited(req, res, email) {
  const ip = A.clientIp(req);
  const [okIp, okEmail] = await Promise.all([
    A.rateLimitOk(`magic:ip:${ip}`, 20, 3600),
    A.rateLimitOk(`magic:email:${email}`, 4, 900)
  ]);
  if (okIp && okEmail) return true;
  res.status(429).json({
    error: 'Too many sign-in attempts. Please wait a few minutes and try again.'
  });
  return false;
}

// ── GET: verify the emailed token, sign the user in ──────────────
async function handleVerify(req, res) {
  // The verify response sets the account cookie — never let it be cached.
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  if (!A.accountsConfigured()) {
    res.status(503).send('Accounts are not enabled yet.');
    return;
  }
  try {
    const token = (req.query.token || '').toString();
    const email = await A.consumeMagicToken(token);
    if (!email) {
      res.writeHead(302, { Location: '/?account=link_invalid' });
      res.end();
      return;
    }
    const user = await A.upsertUser(email);
    if (!user || !user.id) {
      res.status(500).send('Could not complete sign-in. Please try again.');
      return;
    }
    res.setHeader('Set-Cookie', A.makeAccountCookie(user.id, user.email));
    res.writeHead(302, { Location: '/?account=connected' });
    res.end();
  } catch (e) {
    console.error('magic verify error:', e.message);
    await O.reportError(e, { req, where: 'auth:magic:verify' });
    res.status(500).send('Sign-in error. Please request a new link.');
  }
}

// ── POST: send a magic link ──────────────────────────────────────
async function handleRequest(req, res) {
  if (!A.accountsConfigured() || !A.emailConfigured()) {
    res.status(503).json({ error: 'Accounts are not enabled yet.' });
    return;
  }
  try {
    const body = await readJsonBody(req);
    const email = A.normEmail(body.email);
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      res.status(400).json({ error: 'Please enter a valid email address.' });
      return;
    }
    if (!(await rateLimited(req, res, email))) return;
    const token = await A.saveMagicToken(email, 15);
    await A.sendMagicLink(email, token);
    res.status(200).json({ ok: true, sent: true });
  } catch (e) {
    console.error('magic request error:', e.message);
    await O.reportError(e, { req, where: 'auth:magic:request' });
    res.status(500).json({ error: 'Could not send sign-in link. Please try again.' });
  }
}

// ── POST ?mode=onboard: create account + profile, sign in on this device ──
// New email, or an existing email with NO stored connections → create/find the
// user, save the profile, set the account session cookie HERE, return mode:'session'.
// Existing email that ALREADY has connections → never auto-grant a session (would
// let someone hijack an account by typing its email). Instead email a link and
// return mode:'link_sent'.
async function handleOnboard(req, res) {
  if (!A.accountsConfigured()) {
    res.status(503).json({ error: 'Accounts are not enabled yet.' });
    return;
  }
  try {
    const body = await readJsonBody(req);
    const email = A.normEmail(body.email);
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      res.status(400).json({ error: 'Please enter a valid email address.' });
      return;
    }
    if (!(await rateLimited(req, res, email))) return;
    const first_name = String(body.first_name || '').trim().slice(0, 80);
    const last_name = String(body.last_name || '').trim().slice(0, 80);

    const existing = await A.findUser(email);
    if (existing && (await A.userHasConnections(existing.id))) {
      // Protect a real account: require the emailed link to take over this device.
      if (A.emailConfigured()) {
        const token = await A.saveMagicToken(email, 15);
        await A.sendMagicLink(email, token);
      }
      res.status(200).json({ ok: true, mode: 'link_sent' });
      return;
    }

    const user = existing || (await A.upsertUser(email));
    if (!user || !user.id) {
      res.status(500).json({ error: 'Could not create your account. Please try again.' });
      return;
    }
    await A.upsertProfile(user.id, { first_name, last_name }).catch((e) =>
      console.error('onboard profile save:', e.message)
    );
    res.setHeader('Set-Cookie', A.makeAccountCookie(user.id, user.email));
    res.status(200).json({ ok: true, mode: 'session', email: user.email });
  } catch (e) {
    console.error('onboard error:', e.message);
    await O.reportError(e, { req, where: 'auth:magic:onboard' });
    res.status(500).json({ error: 'Could not create your account. Please try again.' });
  }
}

module.exports = async (req, res) => {
  // A token in the query means this is the click-through from the email → verify.
  if (req.method === 'GET' && req.query && req.query.token) {
    return handleVerify(req, res);
  }
  if (req.method === 'POST') {
    const mode = (req.query && req.query.mode) || '';
    if (mode === 'onboard') return handleOnboard(req, res);
    return handleRequest(req, res);
  }
  res.setHeader('Allow', 'GET, POST');
  res.status(405).json({ error: 'Method not allowed' });
};

// Error monitoring: re-wrap the handler so any uncaught throw is reported
// to Sentry (inert until SENTRY_DSN is set). See api/_lib/observe.js.
module.exports = require('../../_lib/observe').wrap(module.exports, 'auth:magic');
