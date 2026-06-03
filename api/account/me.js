// api/account/me.js
// "Who am I?" probe the frontend hits on bootstrap. Returns the signed-in
// email and which platforms have an account-stored session. Always 200 so
// the frontend can branch cleanly on { signedIn: bool }.

const A = require('../_lib/accounts');

module.exports = async (req, res) => {
  if (!A.accountsConfigured()) {
    res.status(200).json({ signedIn: false, enabled: false });
    return;
  }
  const acct = A.readAccount(req);
  if (!acct) {
    res.status(200).json({ signedIn: false, enabled: true });
    return;
  }
  // Best-effort: report which platforms this account has stored sessions for.
  let platforms = [];
  try {
    const checks = await Promise.all(
      ['espn', 'yahoo'].map(async (p) => ((await A.getPlatformSession(acct.uid, p)) ? p : null))
    );
    platforms = checks.filter(Boolean);
  } catch (e) {
    // Non-fatal — still report the signed-in identity.
    console.error('account/me platform check:', e.message);
  }
  res.status(200).json({ signedIn: true, enabled: true, email: acct.email, platforms });
};
