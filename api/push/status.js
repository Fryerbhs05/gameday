// api/push/status.js
// Scheduled status alerts (Vercel Cron — see vercel.json):
//   ?job=snf  every 5 min Sunday night → "Sunday night is final." about 10 minutes
//             after the last Sunday game ends (gives platform points time to settle).
//   ?job=tue  hourly on Tuesday → "Week N is final." at ~9am in each device's time zone.
//   ?job=mnf  every minute Monday evening (ET) → "A Monday night heads-up" ~5 minutes
//             before the FIRST Monday kickoff, naming every starter (either side) in
//             a Monday game whose matchup is still in play. One alert covers a
//             doubleheader. Accounts with nothing in play on Monday get nothing.
// Each account's matchups are read live from its own Sleeper / ESPN / Yahoo
// connections (api/_lib/league-reader.js) — no dependence on the app being open.
// One alert per device per week per job (push_sends dedupe).
// Auth: Vercel Cron's "Authorization: Bearer $CRON_SECRET"; fails closed.

const A = require('../_lib/accounts');
const W = require('../_lib/webpush');
const O = require('../_lib/observe');
const S = require('../_lib/status-alerts');

const SETTLE_MS = 10 * 60000;

async function claim(subId, kind, key) {
  const rows = await A.sbFetch('push_sends?on_conflict=subscription_id,kind,key', {
    method: 'POST',
    headers: { Prefer: 'resolution=ignore-duplicates,return=representation' },
    body: JSON.stringify([{ subscription_id: subId, kind, key }])
  });
  return Array.isArray(rows) && rows.length > 0;
}
async function deliver(sub, message, ttl) {
  const r = await W.sendPush(sub, message, { ttl: ttl || 6 * 3600 });
  if (r.gone) await A.sbFetch(`push_subscriptions?id=eq.${sub.id}`, { method: 'DELETE', headers: { Prefer: 'return=minimal' } }).catch(() => {});
  else await A.sbFetch(`push_subscriptions?id=eq.${sub.id}`, {
    method: 'PATCH', headers: { Prefer: 'return=minimal' },
    body: JSON.stringify(r.ok ? { last_sent_at: new Date().toISOString(), fail_count: 0 } : { fail_count: (sub.fail_count || 0) + 1 })
  }).catch(() => {});
  if (!r.ok) console.error('status push failed', sub.id, r.status, r.text);
  return r.ok;
}
async function jobState(id) {
  const rows = await A.sbFetch(`push_job_state?id=eq.${encodeURIComponent(id)}&select=data`);
  return (rows && rows[0] && rows[0].data) || null;
}
async function setJobState(id, data) {
  await A.sbFetch('push_job_state?on_conflict=id', {
    method: 'POST', headers: { Prefer: 'resolution=merge-duplicates,return=minimal' },
    body: JSON.stringify([{ id, data, updated_at: new Date().toISOString() }])
  });
}

async function subsFor(pref) {
  return (await A.sbFetch(
    `push_subscriptions?select=id,user_id,endpoint,p256dh,auth,tz,fail_count,prefs&or=(prefs->>${pref}.is.null,prefs->>${pref}.eq.true)`
  )) || [];
}

// Build once per account, send to each of its devices that hasn't had it yet.
async function sendToSubs(subs, mode, key, ctx, opts) {
  const byUser = {};
  subs.forEach((s) => { (byUser[s.user_id] = byUser[s.user_id] || []).push(s); });
  let sent = 0, users = 0, empty = 0;
  for (const uid of Object.keys(byUser)) {
    let built = null;
    try { built = await S.buildForUser(uid, mode, ctx); }
    catch (e) { console.error('status build failed', uid, e.message); continue; }
    if (!built) { empty++; continue; }
    users++;
    for (const sub of byUser[uid]) {
      if (!(await claim(sub.id, mode, key))) continue;
      if (await deliver(sub, built.message, opts && opts.ttl)) sent++;
    }
  }
  return { users, empty, sent };
}

async function runSnf(now) {
  const ns = await S.nflState();
  if (!ns.season || !ns.week || (ns.type !== 'regular' && ns.type !== 'post')) return { skipped: `season_type ${ns.type}` };
  const games = await S.weekGames(ns.season, ns.week, ns.type);
  const sunday = games.events.filter((e) => e.sunday);
  if (!sunday.length) return { skipped: 'no Sunday games this week' };
  if (!sunday.every((e) => e.state === 'post')) return { waiting: 'Sunday games still on' };
  const key = `${ns.season}-${ns.week}`, jid = `snf:${key}`;
  const st = (await jobState(jid)) || {};
  if (!st.finalSeenAt) { await setJobState(jid, { finalSeenAt: now }); return { waiting: 'Sunday final, letting points settle' }; }
  if (now - st.finalSeenAt < SETTLE_MS) return { waiting: 'letting points settle' };
  const out = await sendToSubs(await subsFor('snf'), 'snf', key, { ns, games });
  return { job: 'snf', key, ...out };
}

// Send window for the Monday heads-up: the first per-minute run that lands 6½ to
// 1 minute before kickoff does the work (so it reads "Kickoff in 5." honestly).
const MNF_WINDOW_MAX = 6.5 * 60000, MNF_WINDOW_MIN = 60000, MNF_LOCK_MS = 4 * 60000;
async function runMnf(now) {
  const ns = await S.nflState();
  if (!ns.season || !ns.week || (ns.type !== 'regular' && ns.type !== 'post')) return { skipped: `season_type ${ns.type}` };
  const games = await S.weekGames(ns.season, ns.week, ns.type);
  const slate = S.mondaySlate(games);
  if (!slate) return { skipped: 'no Monday game this week' };
  const lead = slate.kickoff - now;
  if (lead > MNF_WINDOW_MAX || lead < MNF_WINDOW_MIN) return { waiting: 'outside window', kickoff: new Date(slate.kickoff).toISOString() };
  const key = `${ns.season}-${ns.week}`, jid = `mnf:${key}`;
  // A build can outlast one minute; the next cron run steps aside instead of
  // re-reading every account (push_sends would still stop a double send).
  const st = (await jobState(jid)) || {};
  if (st.doneAt || (st.startedAt && now - st.startedAt < MNF_LOCK_MS)) return { skipped: 'already running or sent' };
  await setJobState(jid, { startedAt: now });
  const out = await sendToSubs(await subsFor('mnf'), 'mnf', key, { ns, games },
    { ttl: Math.max(60, Math.round((slate.kickoff - Date.now()) / 1000)) });
  await setJobState(jid, { startedAt: now, doneAt: Date.now(), ...out });
  return { job: 'mnf', key, kickoff: new Date(slate.kickoff).toISOString(), ...out };
}

function localParts(tz, now) {
  try {
    const o = {};
    new Intl.DateTimeFormat('en-US', { timeZone: tz || 'America/Chicago', weekday: 'short', hour: '2-digit', hourCycle: 'h23' })
      .formatToParts(new Date(now)).forEach((p) => { o[p.type] = p.value; });
    return { weekday: o.weekday, hour: +o.hour };
  } catch (e) { return localParts('America/Chicago', now); }
}

async function runTue(now) {
  const ns = await S.nflState();
  if (!ns.season || !ns.week || (ns.type !== 'regular' && ns.type !== 'post')) return { skipped: `season_type ${ns.type}` };
  // Only devices where it's Tuesday 9–11am local (dedupe keeps it to one).
  const subs = (await subsFor('tue')).filter((s) => { const p = localParts(s.tz, now); return p.weekday === 'Tue' && p.hour >= 9 && p.hour <= 11; });
  if (!subs.length) return { waiting: 'no devices at 9am local yet' };
  const week = await S.completedWeek(ns);
  const out = await sendToSubs(subs, 'tue', `${ns.season}-${week}`, { ns, week });
  return { job: 'tue', week, ...out };
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const secret = process.env.CRON_SECRET;
  if (!secret || req.headers.authorization !== `Bearer ${secret}`) { res.status(401).json({ error: 'unauthorized' }); return; }
  if (!A.accountsConfigured() || !W.pushConfigured()) { res.status(200).json({ skipped: 'push not configured' }); return; }
  try {
    const job = (req.query && req.query.job) || '';
    const now = Date.now();
    const out = job === 'tue' ? await runTue(now) : job === 'snf' ? await runSnf(now) : job === 'mnf' ? await runMnf(now) : { error: 'unknown job' };
    res.status(200).json(out);
  } catch (e) {
    console.error('status cron error:', e.message);
    await O.reportError(e, { req, where: 'push:status' });
    res.status(500).json({ error: e.message });
  }
};

module.exports = require('../_lib/observe').wrap(module.exports, 'push:status');
module.exports._test = { runSnf, runTue, runMnf, localParts };
