// api/auth/logout.js
// Clears the session cookie so the user is "logged out" of Yahoo.

module.exports = (req, res) => {
  res.setHeader('Set-Cookie', [
    `yahoo_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
    `yahoo_oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
  ]);
  res.writeHead(302, { Location: '/?yahoo=disconnected' });
  res.end();
};
