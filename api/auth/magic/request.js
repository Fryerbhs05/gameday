// api/auth/magic/request.js
// Combined magic-link endpoint (kept as ONE Vercel function to stay under the
// Hobby plan's 12-function limit):
//   POST /api/auth/magic/request               { email }                 -> mint token + email link
//   POST /api/auth/magic/request?mode=onboard  { email, first_name, last_name }
//                                                 -> create account + profile, sign in
//                                                    on THIS device (new/empty email), or
//                                                    email a link (existing email w/ data)
//   GET  /api/auth/magic/request?token=...      -> verify + sign in (the emailed link points here)
//   POST /api/auth/magic/request?mode=code     { email, code }          -> verify the 6-digit emailed
//                                                    code + sign in on THIS device (the only way
//                                                    to sign in an iPhone Home Screen app, since
//                                                    the emailed link always opens Safari)
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

// Mint a link token + a 6-digit code and email both. The code is best-effort:
// if saving it fails, the email still goes out with the link alone.
async function issueSignIn(email) {
  const token = await A.saveMagicToken(email, 15);
  let code = null;
  try {
    code = await A.saveSignInCode(email, 15);
  } catch (e) {
    console.error('sign-in code save failed (link still sent):', e.message);
    await O.reportError(e, { where: 'auth:magic:code-save' });
  }
  await A.sendMagicLink(email, token, code);
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
    // One sign-in retires the whole email: the code sent alongside this link dies too.
    await A.clearMagicTokens(email).catch(() => {});
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
    await issueSignIn(email);
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
        await issueSignIn(email);
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

// ── POST ?mode=code: verify the 6-digit emailed code, sign in on this device ──
// Guessing: a code is 1 in 1,000,000 and lives 15 minutes; 5 tries per email per
// 15 minutes (plus 30/hour per IP) keeps the odds of a lucky guess negligible.
// A wrong code and an unknown email get the same answer (no enumeration).
async function handleCode(req, res) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  if (!A.accountsConfigured()) {
    res.status(503).json({ error: 'Accounts are not enabled yet.' });
    return;
  }
  try {
    const body = await readJsonBody(req);
    const email = A.normEmail(body.email);
    const code = String(body.code || '').replace(/\D/g, '');
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || code.length !== 6) {
      res.status(400).json({ error: 'Enter the 6-digit code from the email.' });
      return;
    }
    const ip = A.clientIp(req);
    const [okIp, okEmail] = await Promise.all([
      A.rateLimitOk(`magic:code:ip:${ip}`, 30, 3600),
      A.rateLimitOk(`magic:code:email:${email}`, 5, 900)
    ]);
    if (!okIp || !okEmail) {
      res.status(429).json({ error: 'Too many tries. Request a new code in a few minutes.' });
      return;
    }
    const valid = await A.checkSignInCode(email, code);
    if (!valid) {
      res.status(400).json({ error: "That code didn't work. Check it, or request a new one." });
      return;
    }
    await A.clearMagicTokens(valid).catch(() => {});
    const user = await A.upsertUser(valid);
    if (!user || !user.id) {
      res.status(500).json({ error: 'Could not complete sign-in. Please try again.' });
      return;
    }
    res.setHeader('Set-Cookie', A.makeAccountCookie(user.id, user.email));
    res.status(200).json({ ok: true, email: user.email });
  } catch (e) {
    console.error('magic code error:', e.message);
    await O.reportError(e, { req, where: 'auth:magic:code' });
    res.status(500).json({ error: 'Sign-in error. Please try again.' });
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
    if (mode === 'code') return handleCode(req, res);
    return handleRequest(req, res);
  }
  res.setHeader('Allow', 'GET, POST');
  res.status(405).json({ error: 'Method not allowed' });
};

// Error monitoring: re-wrap the handler so any uncaught throw is reported
// to Sentry (inert until SENTRY_DSN is set). See api/_lib/observe.js.
module.exports = require('../../_lib/observe').wrap(module.exports, 'auth:magic');
