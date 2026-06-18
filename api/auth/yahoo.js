// api/auth/yahoo.js
// Starts the Yahoo OAuth flow. User hits this endpoint, we generate a
// random "state" (anti-CSRF token), stash it in a short-lived cookie,
// and redirect the browser to Yahoo's login/consent page.

const crypto = require('crypto');

module.exports = (req, res) => {
  const clientId = process.env.YAHOO_CLIENT_ID;
  const redirectUri = process.env.YAHOO_REDIRECT_URI;

  if (!clientId || !redirectUri) {
    res.status(500).send('Yahoo OAuth not configured (missing env vars)');
    return;
  }

  // Random state to tie the callback back to this request. When the connect
  // wizard opens this in a NEW TAB (?wizard=1), we append a ".w" marker to the
  // state so the callback knows to show a "close this tab" page instead of
  // reloading the whole app in that tab. The marker round-trips through Yahoo
  // and is validated against the cookie exactly like the rest of the state.
  const wiz = (req.query && (req.query.wizard === '1' || req.query.wizard === 'true')) ? '.w' : '';
  const state = crypto.randomBytes(16).toString('hex') + wiz;

  res.setHeader(
    'Set-Cookie',
    `yahoo_oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`
  );

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    state: state,
    language: 'en-us'
  });

  const authUrl = `https://api.login.yahoo.com/oauth2/request_auth?${params.toString()}`;
  res.writeHead(302, { Location: authUrl });
  res.end();
};

// Error monitoring: re-wrap the handler so any uncaught throw is reported
// to Sentry (inert until SENTRY_DSN is set). See api/_lib/observe.js.
module.exports = require('../_lib/observe').wrap(module.exports, 'auth:yahoo');
