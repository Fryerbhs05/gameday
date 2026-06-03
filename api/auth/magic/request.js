// api/auth/magic/request.js
// Combined magic-link endpoint (kept as ONE Vercel function to stay under the
// Hobby plan's 12-function limit):
//   POST /api/auth/magic/request        { email }  -> mint token + email link
//   GET  /api/auth/magic/request?token=...         -> verify + sign in (the
//                                                      emailed link points here)
//
// We always respond 200 to the POST (no account enumeration) unless the
// feature isn't configured yet.

const A = require('../../_lib/accounts');

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

// ── GET: verify the emailed token, sign the user in ──────────────
async function handleVerify(req, res) {
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
    const token = await A.saveMagicToken(email, 15);
    await A.sendMagicLink(email, token);
    res.status(200).json({ ok: true, sent: true });
  } catch (e) {
    console.error('magic request error:', e.message);
    res.status(500).json({ error: 'Could not send sign-in link. Please try again.' });
  }
}

module.exports = async (req, res) => {
  // A token in the query means this is the click-through from the email → verify.
  if (req.method === 'GET' && req.query && req.query.token) {
    return handleVerify(req, res);
  }
  if (req.method === 'POST') {
    return handleRequest(req, res);
  }
  res.setHeader('Allow', 'GET, POST');
  res.status(405).json({ error: 'Method not allowed' });
};
