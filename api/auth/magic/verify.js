// api/auth/magic/verify.js
// Step 2 of magic-link sign-in. The user clicks the emailed link:
//   GET /api/auth/magic/verify?token=...
// We consume the token (single use), upsert the user, set an encrypted
// account_session cookie, and bounce them back into the app.

const A = require('../../_lib/accounts');

module.exports = async (req, res) => {
  if (!A.accountsConfigured()) {
    res.status(503).send('Accounts are not enabled yet.');
    return;
  }
  try {
    const token = (req.query.token || '').toString();
    const email = await A.consumeMagicToken(token);
    if (!email) {
      // Expired, already used, or bogus.
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
    console.error('magic/verify error:', e.message);
    res.status(500).send('Sign-in error. Please request a new link.');
  }
};
