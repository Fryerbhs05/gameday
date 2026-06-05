// api/auth/logout.js
// Clears the Yahoo session cookie so the user is "logged out" of Yahoo.
//
// As with ESPN, a connection lives in TWO places: the per-browser cookie (below)
// AND a copy stored against the signed-in account so it can follow the user
// across devices (see api/yahoo/data.js, which falls back to the account copy
// when the cookie is gone). Clearing only the cookie would let that account copy
// re-connect on the next load. So we also delete the account-stored Yahoo
// platform session here. This removes ONLY the connection blob — analytics,
// profile, and account data live in separate tables and are untouched.

// Optional accounts layer — inert unless Supabase env vars are configured.
let A = null;
try { A = require('../_lib/accounts'); } catch (e) { A = null; }

module.exports = async (req, res) => {
  res.setHeader('Set-Cookie', [
    `yahoo_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
    `yahoo_oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
  ]);

  // Best-effort: drop the account-stored Yahoo session so disconnect actually
  // sticks. Non-fatal — a signed-out (cookie-only) user has no account copy.
  try {
    if (A && A.accountsConfigured()) {
      const acct = A.readAccount(req);
      if (acct) await A.deletePlatformSession(acct.uid, 'yahoo');
    }
  } catch (e) {
    console.error('auth/logout account clear failed (non-fatal):', e.message);
  }

  res.writeHead(302, { Location: '/?yahoo=disconnected' });
  res.end();
};
