// api/espn/disconnect.js
// Clears the ESPN session cookie. Frontend hits this when the user clicks
// "Disconnect ESPN". Mirror of /api/auth/logout for the Yahoo side.
//
// A connection lives in TWO places: the per-browser cookie (below) AND a copy
// stored against the signed-in account so it can follow the user across devices
// (see api/espn/status.js, which falls back to the account copy when the cookie
// is gone). If we only cleared the cookie, that account copy would re-connect
// every league on the next page load. So we also delete the account-stored ESPN
// platform session here. This removes ONLY the connection blob — analytics,
// profile, and account data live in separate tables and are untouched.

// Optional accounts layer — inert unless Supabase env vars are configured.
let A = null;
try { A = require('../_lib/accounts'); } catch (e) { A = null; }

module.exports = async (req, res) => {
  res.setHeader(
    'Set-Cookie',
    `espn_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
  );

  // Best-effort: drop the account-stored ESPN session so disconnect actually
  // sticks. Non-fatal — a signed-out (cookie-only) user simply has no account
  // copy to clear.
  try {
    if (A && A.accountsConfigured()) {
      const acct = A.readAccount(req);
      if (acct) await A.deletePlatformSession(acct.uid, 'espn');
    }
  } catch (e) {
    console.error('espn/disconnect account clear failed (non-fatal):', e.message);
  }

  // Allow both GET (for direct browser visits) and POST (from frontend fetch).
  if (req.method === 'POST') {
    res.status(200).json({ ok: true });
  } else {
    res.writeHead(302, { Location: '/?espn=disconnected' });
    res.end();
  }
};

// Error monitoring: re-wrap the handler so any uncaught throw is reported
// to Sentry (inert until SENTRY_DSN is set). See api/_lib/observe.js.
module.exports = require('../_lib/observe').wrap(module.exports, 'espn:disconnect');
