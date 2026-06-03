// api/account/delete.js
// Hard "delete my account and data" — required because we now hold an email +
// encrypted platform credentials. Wipes platform_sessions, magic_tokens, and
// the user row, then clears the account cookie. Irreversible by design.
//
// POST only (so it can't be triggered by a stray link/prefetch).

const A = require('../_lib/accounts');

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }
  if (!A.accountsConfigured()) {
    res.status(503).json({ error: 'Accounts are not enabled.' });
    return;
  }
  const acct = A.readAccount(req);
  if (!acct) {
    res.status(401).json({ error: 'Not signed in.' });
    return;
  }
  try {
    await A.deleteUserData(acct.uid, acct.email);
    res.setHeader('Set-Cookie', A.clearAccountCookie());
    res.status(200).json({ ok: true, deleted: true });
  } catch (e) {
    console.error('account/delete error:', e.message);
    res.status(500).json({ error: 'Could not delete account. Please try again.' });
  }
};
