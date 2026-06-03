// api/account/me.js
// Combined account endpoint (kept as ONE Vercel function to stay under the
// Hobby plan's 12-function limit):
//   GET  /api/account/me                  -> who am I + connected platforms
//   POST /api/account/me?action=logout    -> clear the account cookie
//   POST /api/account/me?action=delete    -> permanently delete account + data

const A = require('../_lib/accounts');

// ── GET: identity + connected platforms ──────────────────────────
async function handleMe(req, res) {
  if (!A.accountsConfigured()) {
    res.status(200).json({ signedIn: false, enabled: false });
    return;
  }
  const acct = A.readAccount(req);
  if (!acct) {
    res.status(200).json({ signedIn: false, enabled: true });
    return;
  }
  let platforms = [];
  try {
    const checks = await Promise.all(
      ['espn', 'yahoo'].map(async (p) => ((await A.getPlatformSession(acct.uid, p)) ? p : null))
    );
    platforms = checks.filter(Boolean);
  } catch (e) {
    console.error('account/me platform check:', e.message);
  }
  res.status(200).json({ signedIn: true, enabled: true, email: acct.email, platforms });
}

// ── POST ?action=logout: end session on this device ──────────────
function handleLogout(req, res) {
  res.setHeader('Set-Cookie', A.clearAccountCookie());
  res.status(200).json({ ok: true });
}

// ── POST ?action=delete: erase account + all stored sessions ─────
async function handleDelete(req, res) {
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
}

module.exports = async (req, res) => {
  // Identity is per-cookie and must never be cached — otherwise a browser can
  // re-render a stale account after the session cookie changes (e.g. clicking a
  // magic link that switches accounts). Force a fresh read every time.
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  if (req.method === 'GET') return handleMe(req, res);
  if (req.method === 'POST') {
    const action = (req.query && req.query.action) || '';
    if (action === 'logout') return handleLogout(req, res);
    if (action === 'delete') return handleDelete(req, res);
    res.status(400).json({ error: 'Unknown action' });
    return;
  }
  res.setHeader('Allow', 'GET, POST');
  res.status(405).json({ error: 'Method not allowed' });
};
