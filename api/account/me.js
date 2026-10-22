// api/account/me.js
// Combined account endpoint (kept as ONE Vercel function to stay under the
// Hobby plan's 12-function limit):
//   GET  /api/account/me                   -> who am I + connected platforms
//   POST /api/account/me?action=logout     -> clear the account cookie
//   POST /api/account/me?action=delete     -> permanently delete account + data
//   POST /api/account/me?action=sleeper    -> save/clear the Sleeper username
//   POST /api/account/me?action=manual     -> save the manually entered leagues
//   POST /api/account/me?action=leaguemap  -> record which real leagues this
//        account is in (league_connections) for league-reach analytics
//   POST /api/account/me?action=shoutouts  -> Settings "Do not share my wins"
//        body { noShoutouts: true|false }
//        body { username } saves it; empty/missing username clears it.

const A = require('../_lib/accounts');

async function readJsonBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') {
    try { return JSON.parse(req.body); } catch { return {}; }
  }
  return await new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch { resolve({}); } });
    req.on('error', () => resolve({}));
  });
}

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
  let sleeperUsername = null;
  try {
    const blobs = await Promise.all(
      ['espn', 'yahoo', 'sleeper'].map((p) => A.getPlatformSession(acct.uid, p))
    );
    ['espn', 'yahoo', 'sleeper'].forEach((p, i) => { if (blobs[i]) platforms.push(p); });
    // Sleeper's blob is just the (non-credential) username, encrypted for
    // storage consistency. Decode it so the client can rehydrate the field.
    if (blobs[2]) {
      try { sleeperUsername = JSON.parse(A.decrypt(blobs[2])).u || null; } catch (e) { sleeperUsername = null; }
    }
  } catch (e) {
    console.error('account/me platform check:', e.message);
  }
  // Signup name lives in user_profiles (captured in the onboarding identity step).
  // Surface it so the Account view can greet the user by name. Older accounts may
  // have no profile row → name stays null and the client shows a graceful fallback.
  let name = null;
  try {
    const profile = await A.getProfile(acct.uid);
    if (profile) {
      const full = [profile.first_name, profile.last_name].filter(Boolean).join(' ').trim();
      name = full || null;
    }
  } catch (e) {
    console.error('account/me profile read:', e.message);
  }
  // Account-level "global exclude" list — leagues the user switched OFF in the
  // Account view. The client drops these from the calculation layer on load so
  // the exclusion follows across devices. Best-effort: failure → empty list.
  // Read the disabled list and the manual leagues in PARALLEL and independently:
  // a failure in one (e.g. the manual_leagues column missing) must never cost the
  // other. manualLeagues stays undefined on failure so the client keeps its own
  // copy instead of treating the account as empty.
  let disabledLeagues = [];
  let manualLeagues;
  let noShoutouts; // undefined on a failed read → the client keeps what it has
  await Promise.all([
    A.getNoShoutouts(acct.uid).then((v) => { noShoutouts = v; })
      .catch((e) => console.error('account/me shoutouts read:', e.message)),
    A.getDisabledLeagues(acct.uid).then((v) => { disabledLeagues = v; })
      .catch((e) => console.error('account/me disabled-leagues read:', e.message)),
    A.getManualLeagues(acct.uid).then((v) => { manualLeagues = v; })
      .catch((e) => console.error('account/me manual-leagues read:', e.message))
  ]);
  // ── Rolling session ────────────────────────────────────────────
  // The account cookie was issued at sign-in with a hard 30-day Max-Age and
  // never refreshed, so an actively-used device got silently signed out exactly
  // 30 days later. The symptom was confusing rather than obvious: ACCOUNT-ONLY
  // connections (ESPN on a phone, which has no espn_session cookie of its own)
  // vanished, while localStorage-backed Sleeper stayed put — so it read as
  // "ESPN broke on mobile" while the desktop, authing off its own espn_session
  // cookie, looked fine. This endpoint runs on every app load, so re-issuing
  // here makes the session 30 days of INACTIVITY instead of 30 days absolute.
  // Refresh only once the cookie is a day old so we're not stamping a
  // Set-Cookie on every request. Best-effort — never block the response.
  // This also silently UPGRADES every cookie still carrying the old 30-day exp:
  // its remaining life is far below the new window, so the next load re-issues
  // it at 400 days with nothing asked of the user.
  try {
    const LIFETIME = A.ACCOUNT_SESSION_SECS;
    const REFRESH_AFTER = 86400;   // re-issue once the cookie is >1 day old
    const remaining = (acct.exp || 0) - Math.floor(Date.now() / 1000);
    if (!acct.exp || remaining < LIFETIME - REFRESH_AFTER) {
      res.setHeader('Set-Cookie', A.makeAccountCookie(acct.uid, acct.email));
    }
  } catch (e) {
    console.error('account/me session refresh (non-fatal):', e.message);
  }
  res
    .status(200)
    .json({ signedIn: true, enabled: true, email: acct.email, name, platforms, sleeper: sleeperUsername, disabledLeagues, manualLeagues, noShoutouts });
}

// ── POST ?action=logout: end session on this device ──────────────
// Cookie-clear strings for the per-browser platform sessions. Sign-out clears
// these so leagues are HIDDEN while the user is signed out — but it does NOT
// delete the account-stored copies, so they reappear automatically on the next
// sign-in. (Disconnect is the one that deletes the stored copies; see
// api/espn/disconnect.js + api/auth/logout.js.)
const CLEAR_PLATFORM_COOKIES = [
  `espn_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
  `yahoo_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
  `yahoo_oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
];

function handleLogout(req, res) {
  // Clear the account cookie AND the per-browser platform cookies so the user's
  // leagues disappear on sign-out. Account-stored copies are untouched, so a
  // later sign-in restores everything with nothing to re-enter.
  res.setHeader('Set-Cookie', [A.clearAccountCookie(), ...CLEAR_PLATFORM_COOKIES]);
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
    // Also clear the per-browser platform cookies — the stored copies are gone
    // server-side, but the browser cookies would still auth directly otherwise.
    res.setHeader('Set-Cookie', [A.clearAccountCookie(), ...CLEAR_PLATFORM_COOKIES]);
    res.status(200).json({ ok: true, deleted: true });
  } catch (e) {
    console.error('account/delete error:', e.message);
    res.status(500).json({ error: 'Could not delete account. Please try again.' });
  }
}

// ── POST ?action=sleeper: save/clear the Sleeper username for this account ──
// Sleeper has no OAuth/credentials — the username alone identifies the user's
// leagues — so we store just that. Encrypted for storage consistency with the
// other platform blobs. An empty username clears the connection.
async function handleSleeper(req, res) {
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
    const body = await readJsonBody(req);
    const username = String((body && body.username) || '').trim();
    if (username) {
      const blob = A.encrypt(JSON.stringify({ u: username }));
      await A.savePlatformSession(acct.uid, 'sleeper', blob);
      res.status(200).json({ ok: true, sleeper: username });
    } else {
      await A.deletePlatformSession(acct.uid, 'sleeper');
      res.status(200).json({ ok: true, sleeper: null });
    }
  } catch (e) {
    console.error('account/sleeper error:', e.message);
    res.status(500).json({ error: 'Could not save Sleeper connection.' });
  }
}

// ── POST ?action=profile: set the signup name when it's still blank ──
// Accounts created via the quick "Sign in" button skip the onboarding name
// step, so this lets the user fill it in from the Account view. By design it
// only FILLS A BLANK name — if a name already exists we leave it untouched
// (the UI only exposes this when the name is empty, and this guards the API too).
async function handleProfile(req, res) {
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
    // Don't clobber an existing name — insert only if currently blank.
    const existing = await A.getProfile(acct.uid);
    const hasName = existing && (existing.first_name || existing.last_name);
    if (hasName) {
      const full = [existing.first_name, existing.last_name].filter(Boolean).join(' ').trim();
      res.status(409).json({ error: 'Name already set.', name: full || null });
      return;
    }
    const body = await readJsonBody(req);
    const first_name = String((body && body.first_name) || '').trim().slice(0, 80);
    const last_name = String((body && body.last_name) || '').trim().slice(0, 80);
    if (!first_name && !last_name) {
      res.status(400).json({ error: 'Enter a name.' });
      return;
    }
    await A.upsertProfile(acct.uid, { first_name, last_name });
    const name = [first_name, last_name].filter(Boolean).join(' ').trim() || null;
    res.status(200).json({ ok: true, name });
  } catch (e) {
    console.error('account/profile error:', e.message);
    res.status(500).json({ error: 'Could not save your name. Please try again.' });
  }
}

// ── POST ?action=leagues: save the account-level disabled-league list ──
// Body { disabledLeagues: ["espn|Dynasty Warriors", ...] }. Replaces the stored
// list wholesale (the client always sends the full current set). Persists the
// "global exclude" so toggled-off leagues stay excluded on every device.
async function handleLeagues(req, res) {
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
    const body = await readJsonBody(req);
    const keys = Array.isArray(body && body.disabledLeagues) ? body.disabledLeagues : [];
    const saved = await A.setDisabledLeagues(acct.uid, keys);
    res.status(200).json({ ok: true, disabledLeagues: saved || [] });
  } catch (e) {
    console.error('account/leagues error:', e.message);
    res.status(500).json({ error: 'Could not save your league settings.' });
  }
}

// ── POST ?action=manual: save the account's manually entered leagues ──
// Body { manualLeagues: [ ... ] }. Replaces the stored array wholesale (the
// client always sends the full current set, including deletions).
async function handleManual(req, res) {
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
    const body = await readJsonBody(req);
    const list = Array.isArray(body && body.manualLeagues) ? body.manualLeagues : [];
    const saved = await A.setManualLeagues(acct.uid, list);
    res.status(200).json({ ok: true, manualLeagues: saved || [] });
  } catch (e) {
    if (e && e.code === 'TOO_LARGE') { res.status(413).json({ error: 'Too much league data.' }); return; }
    console.error('account/manual error:', e.message);
    res.status(500).json({ error: 'Could not save your manual leagues.' });
  }
}

// ── POST ?action=shoutouts: Settings → "Do not share my wins" ──
// Body { noShoutouts: true|false }. true = never name this account's teams in
// Conflicted's social posts. Must be a boolean — anything else is rejected so a
// malformed request can't silently flip someone back to sharing.
async function handleShoutouts(req, res) {
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
    const body = await readJsonBody(req);
    if (!body || typeof body.noShoutouts !== 'boolean') {
      res.status(400).json({ error: 'noShoutouts must be true or false.' });
      return;
    }
    const saved = await A.setNoShoutouts(acct.uid, body.noShoutouts);
    res.status(200).json({ ok: true, noShoutouts: saved });
  } catch (e) {
    console.error('account/shoutouts error:', e.message);
    res.status(500).json({ error: 'Could not save your sharing setting.' });
  }
}

// ── POST ?action=leaguemap: record the real leagues this account is in ──
// Body { season, leagues: [{ platform, league_id, name, size, team_id, co }] }.
// UPSERT only (never deletes): one row per (user, platform, league, season),
// refreshing name/size/team + last_seen_at. Feeds the league_reach view
// ("12-team league, 3 Conflicted accounts"). Analytics — never an error the
// user sees, so failures still answer 204.
const LM_PLATFORMS = new Set(['espn', 'yahoo', 'sleeper']);
function lmStr(v, max) {
  if (v === null || v === undefined) return null;
  const s = String(v).trim();
  return s ? s.slice(0, max) : null;
}
async function handleLeagueMap(req, res) {
  if (!A.accountsConfigured()) { res.status(204).end(); return; }
  const acct = A.readAccount(req);
  if (!acct) { res.status(204).end(); return; }
  try {
    const body = await readJsonBody(req);
    const season = parseInt(body && body.season, 10);
    if (!(season >= 2015 && season <= 2100)) { res.status(204).end(); return; }
    const list = Array.isArray(body && body.leagues) ? body.leagues.slice(0, 60) : [];
    const now = new Date().toISOString();
    const seen = new Set();
    const rows = [];
    for (const l of list) {
      if (!l || !LM_PLATFORMS.has(l.platform)) continue;
      const lid = lmStr(l.league_id, 64);
      if (!lid || seen.has(l.platform + '|' + lid)) continue;
      seen.add(l.platform + '|' + lid);
      const size = parseInt(l.size, 10);
      rows.push({
        user_id: acct.uid,
        platform: l.platform,
        league_id: lid,
        season,
        league_name: lmStr(l.name, 120),
        league_size: size > 0 && size <= 64 ? size : null,
        team_id: lmStr(l.team_id, 64),
        is_co_mgr: !!l.co,
        last_seen_at: now
      });
    }
    if (rows.length) {
      await A.sbFetch('league_connections?on_conflict=user_id,platform,league_id,season', {
        method: 'POST',
        headers: { Prefer: 'resolution=merge-duplicates,return=minimal' },
        body: JSON.stringify(rows)
      });
    }
    res.status(204).end();
  } catch (e) {
    console.error('account/leaguemap error:', e.message);
    res.status(204).end();
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
    if (action === 'sleeper') return handleSleeper(req, res);
    if (action === 'profile') return handleProfile(req, res);
    if (action === 'leagues') return handleLeagues(req, res);
    if (action === 'manual') return handleManual(req, res);
    if (action === 'leaguemap') return handleLeagueMap(req, res);
    if (action === 'shoutouts') return handleShoutouts(req, res);
    res.status(400).json({ error: 'Unknown action' });
    return;
  }
  res.setHeader('Allow', 'GET, POST');
  res.status(405).json({ error: 'Method not allowed' });
};

// Error monitoring: re-wrap the handler so any uncaught throw is reported
// to Sentry (inert until SENTRY_DSN is set). See api/_lib/observe.js.
module.exports = require('../_lib/observe').wrap(module.exports, 'account:me');
