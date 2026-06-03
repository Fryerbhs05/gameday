// api/account/logout.js
// Signs the user out of their Conflicted account by clearing the account
// cookie. Does NOT delete any data — just ends the session on this device.
// Leaves the per-platform Yahoo/ESPN cookies alone (those have their own
// disconnect endpoints).

const A = require('../_lib/accounts');

module.exports = (req, res) => {
  res.setHeader('Set-Cookie', A.clearAccountCookie());
  if (req.method === 'POST') {
    res.status(200).json({ ok: true });
  } else {
    res.writeHead(302, { Location: '/?account=signed_out' });
    res.end();
  }
};
