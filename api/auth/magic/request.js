// api/auth/magic/request.js
// Step 1 of magic-link sign-in. POST { email } → we mint a single-use token,
// store its hash in Supabase, and email the user a link. We ALWAYS respond
// 200 (never reveal whether an email already has an account) unless the
// feature isn't configured yet.
//
// POST body (JSON): { email: "you@example.com" }

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

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }
  if (!A.accountsConfigured() || !A.emailConfigured()) {
    res.status(503).json({ error: 'Accounts are not enabled yet.' });
    return;
  }
  try {
    const body = await readJsonBody(req);
    const email = A.normEmail(body.email);
    // Basic shape check — don't try to fully validate email RFCs.
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      res.status(400).json({ error: 'Please enter a valid email address.' });
      return;
    }

    const token = await A.saveMagicToken(email, 15);
    await A.sendMagicLink(email, token);

    // Uniform success — no account enumeration.
    res.status(200).json({ ok: true, sent: true });
  } catch (e) {
    // Log server-side; give the client a generic message.
    console.error('magic/request error:', e.message);
    res.status(500).json({ error: 'Could not send sign-in link. Please try again.' });
  }
};
