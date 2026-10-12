// api/push/subscribe.js
// Web push subscription endpoint (one function, several actions):
//   GET  /api/push/subscribe                       -> { enabled, publicKey }
//   POST /api/push/subscribe                       { subscription, tz, platform, prefs }
//                                                  -> save this device (signed-in only)
//   POST /api/push/subscribe?action=unsubscribe    { endpoint } -> remove this device
//   POST /api/push/subscribe?action=test           { endpoint } -> send a test alert to this device
//   POST /api/push/subscribe?action=status         { endpoint } -> { subscribed, prefs } for this device
//   POST /api/push/subscribe?action=prefs          { endpoint, prefs } -> update this device's alert types
//   POST /api/push/subscribe?action=roster         { season, week, players } -> live-week snapshot for TD alerts
//   POST /api/push/subscribe?action=test_status    { endpoint, mode:'snf'|'mnf'|'tue' } -> build the Sunday-night /
//                                                  Monday heads-up / Tuesday alert for THIS account right now and send it here
// A subscription always belongs to the signed-in account, so the server knows
// whose leagues an alert is about (needed for the Tuesday results alert).

const A = require('../_lib/accounts');
const S = require('../_lib/status-alerts');
const W = require('../_lib/webpush');
const O = require('../_lib/observe');

// The server POSTs to whatever endpoint the browser hands us, so only accept
// the real push services (no arbitrary URLs).
const PUSH_HOSTS = [
  /^web\.push\.apple\.com$/,
  /^fcm\.googleapis\.com$/,
  /^android\.googleapis\.com$/,
  /^updates\.push\.services\.mozilla\.com$/,
  /\.notify\.windows\.com$/
];
function okEndpoint(ep) {
  try {
    const u = new URL(String(ep || ''));
    return u.protocol === 'https:' && PUSH_HOSTS.some((re) => re.test(u.hostname));
  } catch (e) { return false; }
}

// Preview gate (2026-10-12, Matt): alerts are limited to these accounts, enforced
// HERE as well as in the app (the app's list is cfCanManiac / MANIAC_EMAILS).
// Remove this check to open alerts to everyone.
const PREVIEW_EMAILS = ['fryerm@net.elmhurst.edu', 'riedjeremy@yahoo.com', 'tjboyer90@gmail.com'];
function previewOk(acct) {
  return !!(acct && acct.email && PREVIEW_EMAILS.includes(String(acct.email).trim().toLowerCase()));
}

// Alert types a device can switch on/off. Missing = on.
function cleanPrefs(p) {
  p = p || {};
  return { checkin: p.checkin !== false, td: p.td !== false, snf: p.snf !== false, mnf: p.mnf !== false, tue: p.tue !== false };
}

const TEST_MESSAGE = {
  kind: 'test',
  title: 'Alerts are on.',
  body: "Next one lands an hour before Sunday kickoff.",
  url: '/',
  tag: 'cf-test'
};

async function readJsonBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') { try { return JSON.parse(req.body); } catch { return {}; } }
  return await new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch { resolve({}); } });
    req.on('error', () => resolve({}));
  });
}

async function findSub(endpoint) {
  const rows = await A.sbFetch(
    `push_subscriptions?endpoint=eq.${encodeURIComponent(endpoint)}&select=id,user_id,endpoint,p256dh,auth`
  );
  return rows && rows[0];
}

async function handleSubscribe(req, res, acct) {
  const body = await readJsonBody(req);
  const s = body.subscription || {};
  const keys = s.keys || {};
  if (!okEndpoint(s.endpoint) || !keys.p256dh || !keys.auth) {
    res.status(400).json({ error: 'Invalid subscription.' });
    return;
  }
  const prefs = cleanPrefs(body.prefs);
  const row = {
    user_id: acct.uid,
    endpoint: s.endpoint,
    p256dh: String(keys.p256dh).slice(0, 200),
    auth: String(keys.auth).slice(0, 100),
    tz: body.tz ? String(body.tz).slice(0, 64) : null,
    platform: body.platform ? String(body.platform).slice(0, 40) : null,
    prefs,
    updated_at: new Date().toISOString(),
    fail_count: 0
  };
  // Upsert on endpoint: re-subscribing the same device (or a device that changed
  // accounts) updates the row instead of duplicating it.
  await A.sbFetch('push_subscriptions?on_conflict=endpoint', {
    method: 'POST',
    headers: { Prefer: 'resolution=merge-duplicates,return=minimal' },
    body: JSON.stringify([row])
  });
  res.status(200).json({ ok: true, prefs });
}

async function handleUnsubscribe(req, res, acct) {
  const body = await readJsonBody(req);
  const ep = String(body.endpoint || '');
  if (!ep) { res.status(400).json({ error: 'Missing endpoint.' }); return; }
  await A.sbFetch(
    `push_subscriptions?endpoint=eq.${encodeURIComponent(ep)}&user_id=eq.${acct.uid}`,
    { method: 'DELETE', headers: { Prefer: 'return=minimal' } }
  );
  res.status(200).json({ ok: true });
}

async function handleTest(req, res, acct) {
  const body = await readJsonBody(req);
  const ep = String(body.endpoint || '');
  if (!(await A.rateLimitOk(`push:test:${acct.uid}`, 6, 3600))) {
    res.status(429).json({ error: 'Too many test alerts. Try again later.' });
    return;
  }
  const sub = ep && (await findSub(ep));
  if (!sub || sub.user_id !== acct.uid) {
    res.status(404).json({ error: 'This device is not signed up for alerts.' });
    return;
  }
  const r = await W.sendPush(sub, TEST_MESSAGE, { ttl: 600 });
  if (r.gone) {
    await A.sbFetch(`push_subscriptions?id=eq.${sub.id}`, { method: 'DELETE', headers: { Prefer: 'return=minimal' } }).catch(() => {});
  }
  if (!r.ok) console.error('push test failed', r.status, r.text);
  res.status(r.ok ? 200 : 502).json({ ok: r.ok, status: r.status, gone: r.gone });
}

async function handleStatus(req, res, acct) {
  const body = await readJsonBody(req);
  const ep = String(body.endpoint || '');
  const rows = ep ? await A.sbFetch(
    `push_subscriptions?endpoint=eq.${encodeURIComponent(ep)}&user_id=eq.${acct.uid}&select=prefs`
  ) : [];
  const row = rows && rows[0];
  res.status(200).json({ subscribed: !!row, prefs: row ? cleanPrefs(row.prefs) : null });
}

async function handlePrefs(req, res, acct) {
  const body = await readJsonBody(req);
  const ep = String(body.endpoint || '');
  if (!ep) { res.status(400).json({ error: 'Missing endpoint.' }); return; }
  const prefs = cleanPrefs(body.prefs);
  await A.sbFetch(
    `push_subscriptions?endpoint=eq.${encodeURIComponent(ep)}&user_id=eq.${acct.uid}`,
    { method: 'PATCH', headers: { Prefer: 'return=minimal' }, body: JSON.stringify({ prefs, updated_at: new Date().toISOString() }) }
  );
  res.status(200).json({ ok: true, prefs });
}

// The app posts who's on which side of each matchup this week; the TD poller
// matches scoring players against it. Small: one entry per rostered starter.
async function handleRoster(req, res, acct) {
  const body = await readJsonBody(req);
  const season = String(body.season || '').slice(0, 8);
  const week = parseInt(body.week, 10);
  const arr = Array.isArray(body.players) ? body.players.slice(0, 400) : null;
  if (!season || !(week >= 1 && week <= 25) || !arr) { res.status(400).json({ error: 'Bad snapshot.' }); return; }
  const s80 = (v) => String(v == null ? '' : v).slice(0, 80);
  const lst = (a) => (Array.isArray(a) ? a.slice(0, 30).map(s80) : []);
  const players = arr
    .filter((p) => p && p.sid && /^[A-Za-z0-9]{1,12}$/.test(String(p.sid)))
    .map((p) => ({ sid: String(p.sid), name: s80(p.name), team: s80(p.team).slice(0, 4), pos: s80(p.pos).slice(0, 8), mine: lst(p.mine), opp: lst(p.opp) }));
  await A.sbFetch('push_rosters?on_conflict=user_id', {
    method: 'POST',
    headers: { Prefer: 'resolution=merge-duplicates,return=minimal' },
    body: JSON.stringify([{ user_id: acct.uid, season, week, players, updated_at: new Date().toISOString() }])
  });
  res.status(200).json({ ok: true, players: players.length });
}

// Test send for the status alerts: same builder the crons use, run now, sent to
// this device only. Sunday-night mode uses the CURRENT week as it stands; Tuesday
// mode uses the most recent fully-final week.
async function handleTestStatus(req, res, acct) {
  const body = await readJsonBody(req);
  const ep = String(body.endpoint || '');
  const mode = body.mode === 'tue' ? 'tue' : body.mode === 'mnf' ? 'mnf' : 'snf';
  if (!(await A.rateLimitOk(`push:teststatus:${acct.uid}`, 10, 3600))) {
    res.status(429).json({ error: 'Too many test alerts. Try again later.' }); return;
  }
  const sub = ep && (await findSub(ep));
  if (!sub || sub.user_id !== acct.uid) { res.status(404).json({ error: 'This device is not signed up for alerts.' }); return; }
  // Monday test = preview: Monday games treated as not yet kicked off, so the
  // heads-up can be tried any day of a week that has a Monday game.
  const built = await S.buildForUser(acct.uid, mode, mode === 'mnf' ? { preview: true } : undefined);
  if (!built) {
    const error = mode === 'mnf' ? 'Nothing in play on Monday night this week, so no heads-up would go out.' : 'No matchups found for this week.';
    res.status(200).json({ ok: false, error }); return;
  }
  const r = await W.sendPush(sub, { ...built.message, tag: `cf-test-${mode}` }, { ttl: 600 });
  if (!r.ok) console.error('push test_status failed', r.status, r.text);
  res.status(r.ok ? 200 : 502).json({ ok: r.ok, week: built.week, title: built.message.title, body: built.message.body });
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const enabled = A.accountsConfigured() && W.pushConfigured();
  if (req.method === 'GET') {
    res.status(200).json({ enabled, publicKey: enabled ? W.publicKey() : null });
    return;
  }
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST');
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }
  if (!enabled) { res.status(503).json({ error: 'Alerts are not enabled yet.' }); return; }
  const acct = A.readAccount(req);
  if (!acct) { res.status(401).json({ error: 'Sign in to turn on alerts.' }); return; }
  try {
    const action = (req.query && req.query.action) || '';
    if (action === 'unsubscribe') return await handleUnsubscribe(req, res, acct);
    if (action === 'status') return await handleStatus(req, res, acct);
    if (action === 'prefs') return await handlePrefs(req, res, acct);
    if (!previewOk(acct)) { res.status(403).json({ error: 'Alerts are in preview.' }); return; }
    if (action === 'roster') return await handleRoster(req, res, acct);
    if (action === 'test_status') return await handleTestStatus(req, res, acct);
    if (action === 'test') return await handleTest(req, res, acct);
    return await handleSubscribe(req, res, acct);
  } catch (e) {
    console.error('push subscribe error:', e.message);
    await O.reportError(e, { req, where: 'push:subscribe' });
    res.status(500).json({ error: 'Could not update alerts. Please try again.' });
  }
};

module.exports = require('../_lib/observe').wrap(module.exports, 'push:subscribe');
