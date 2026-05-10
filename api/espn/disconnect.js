// api/espn/disconnect.js
// Clears the ESPN session cookie. Frontend hits this when the user clicks
// "Disconnect ESPN". Mirror of /api/auth/logout for the Yahoo side.

module.exports = (req, res) => {
  res.setHeader(
    'Set-Cookie',
    `espn_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
  );

  // Allow both GET (for direct browser visits) and POST (from frontend fetch).
  if (req.method === 'POST') {
    res.status(200).json({ ok: true });
  } else {
    res.writeHead(302, { Location: '/?espn=disconnected' });
    res.end();
  }
};
