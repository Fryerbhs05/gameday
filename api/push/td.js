// api/push/td.js
// Touchdown alerts poller (Vercel Cron, every minute — see vercel.json).
//
// Each invocation polls Sleeper's live stats TWICE (≈30s apart) while games are
// on. A poll:
//   1. diffs every player's TD counts against the last poll (push_td_state),
//   2. groups new TDs into plays per user (TD pass + catch = one play),
//   3. matches them against each user's live-week snapshot (push_rosters, posted
//      by the app) and sends "X TD. Helps you in A. Hurts you in B." to that
//      user's devices with TD alerts on — Cheer + Conflicted players only,
//   4. a TD that DISAPPEARS from the stats on two polls in a row gets a
//      "called back" alert that replaces the original on the lock screen.
// The first poll of a new week only records a baseline (no alerts for TDs
// that happened before we started watching).
// Every detected TD is written to push_td_log for auditing.
//
// Auth: Vercel Cron sends "Authorization: Bearer $CRON_SECRET"; fails closed.

const A = require('../_lib/accounts');
const W = require('../_lib/webpush');
const O = require('../_lib/observe');
const E = require('../_lib/td-engine');

const SLEEPER = 'https://api.sleeper.app/v1';
const SCOREBOARD = 'https://site.api.espn.com/apis/site/v2/sports/football/nfl/scoreboard';
const STATE_ID = 'td';
const POLL_GAP_MS = 30000;

async function getJson(url) {
  const sep = url.includes('?') ? '&' : '?';
  // Unique URL every time: Sleeper's CDN edge serves stale bytes otherwise
  // (measured 2026-09-10 — cache:'no-store' does NOT get past it).
  const r = await fetch(`${url}${sep}_cb=${Date.now()}`, { headers: { Accept: 'application/json' } });
  if (!r.ok) throw new Error(`${new URL(url).hostname} ${r.status}`);
  return r.json();
}

async function anyGameLive() {
  try {
    const j = await getJson(SCOREBOARD);
    return (j.events || []).some((e) => {
      const s = e && e.competitions && e.competitions[0] && e.competitions[0].status;
      return s && s.type && s.type.state === 'in';
    });
  } catch (e) {
    return null; // unknown — caller polls anyway
  }
}

async function loadState() {
  const rows = await A.sbFetch(`push_td_state?id=eq.${STATE_ID}&select=*`);
  return (rows && rows[0]) || null;
}
async function saveState(st) {
  await A.sbFetch('push_td_state?on_conflict=id', {
    method: 'POST',
    headers: { Prefer: 'resolution=merge-duplicates,return=minimal' },
    body: JSON.stringify([{ ...st, id: STATE_ID, updated_at: new Date().toISOString() }])
  });
}

async function claim(subId, kind, key) {
  const rows = await A.sbFetch('push_sends?on_conflict=subscription_id,kind,key', {
    method: 'POST',
    headers: { Prefer: 'resolution=ignore-duplicates,return=representation' },
    body: JSON.stringify([{ subscription_id: subId, kind, key }])
  });
  return Array.isArray(rows) && rows.length > 0;
}

async function deliver(sub, message) {
  const r = await W.sendPush(sub, message, { ttl: 20 * 60 });
  if (r.gone) {
    await A.sbFetch(`push_subscriptions?id=eq.${sub.id}`, { method: 'DELETE', headers: { Prefer: 'return=minimal' } }).catch(() => {});
  } else {
    const patch = r.ok ? { last_sent_at: new Date().toISOString(), fail_count: 0 } : { fail_count: (sub.fail_count || 0) + 1 };
    await A.sbFetch(`push_subscriptions?id=eq.${sub.id}`, {
      method: 'PATCH', headers: { Prefer: 'return=minimal' }, body: JSON.stringify(patch)
    }).catch(() => {});
  }
  if (!r.ok) console.error('td push failed', sub.id, r.status, r.text);
  return r.ok;
}

// Devices with TD alerts on, grouped by account, plus each account's live-week snapshot.
async function loadAudience(season, week) {
  const subs = (await A.sbFetch(
    'push_subscriptions?select=id,user_id,endpoint,p256dh,auth,fail_count,prefs&or=(prefs->>td.is.null,prefs->>td.eq.true)'
  )) || [];
  if (!subs.length) return [];
  const uids = [...new Set(subs.map((s) => s.user_id))];
  const rosters = (await A.sbFetch(
    `push_rosters?user_id=in.(${uids.join(',')})&select=user_id,season,week,players`
  )) || [];
  const byUser = {};
  for (const r of rosters) {
    if (String(r.season) !== String(season) || +r.week !== +week) continue; // stale week
    const map = {};
    for (const p of r.players || []) if (p && p.sid) map[String(p.sid)] = p;
    byUser[r.user_id] = map;
  }
  return uids
    .filter((u) => byUser[u])
    .map((u) => ({ uid: u, roster: byUser[u], subs: subs.filter((s) => s.user_id === u) }));
}

async function log(row) {
  await A.sbFetch('push_td_log', {
    method: 'POST', headers: { Prefer: 'return=minimal' }, body: JSON.stringify([row])
  }).catch((e) => console.error('td log failed', e.message));
}

async function sendTds(ups, season, week, seasonWeek) {
  const audience = await loadAudience(season, week);
  const tally = {}; // event key -> {devices, sent, sample}
  for (const u of audience) {
    for (const members of E.groupPlays(ups, u.roster)) {
      const alert = E.buildPlayAlert(members, u.roster, seasonWeek);
      if (!alert) continue;
      for (const sub of u.subs) {
        if (!(await claim(sub.id, 'td', alert.key))) continue;
        const ok = await deliver(sub, alert.message);
        for (const m of members) {
          const k = E.memberKey(m);
          const t = (tally[k] = tally[k] || { devices: 0, sent: 0, sample: alert.message });
          t.devices++; if (ok) t.sent++;
        }
      }
    }
  }
  for (const e of ups) {
    const k = E.memberKey(e);
    const t = tally[k] || { devices: 0, sent: 0, sample: null };
    await log({ season: String(season), week: +week, kind: 'td', players: [e], devices: t.devices, sent: t.sent, sample: t.sample });
  }
}

async function sendCalledBack(downs, season, week, seasonWeek) {
  const audience = await loadAudience(season, week);
  for (const d of downs) {
    let devices = 0, sent = 0, sample = null;
    const member = E.memberKey({ sid: d.sid, cat: d.cat, to: d.from, rev: d.rev });
    for (const u of audience) {
      if (!u.roster[d.sid]) continue;
      for (const sub of u.subs) {
        // Only devices that actually got the original alert.
        const rows = (await A.sbFetch(
          `push_sends?subscription_id=eq.${sub.id}&kind=eq.td&key=like.${encodeURIComponent(seasonWeek + '|*' + member + '*')}&select=key`
        )) || [];
        const orig = rows.find((r) => String(r.key).split('|').slice(1).includes(member));
        if (!orig) continue;
        if (!(await claim(sub.id, 'td_cb', orig.key))) continue;
        const msg = E.buildCalledBack(orig.key, d.sid, u.roster);
        devices++; sample = msg;
        if (await deliver(sub, msg)) sent++;
      }
    }
    await log({ season: String(season), week: +week, kind: 'called_back', players: [d], devices, sent, sample });
  }
}

// One poll. Returns a summary for the response/logs.
async function pollOnce() {
  const nfl = await getJson(`${SLEEPER}/state/nfl`);
  const season = String(nfl.season || nfl.league_season || '');
  const week = +(nfl.week || 0);
  const type = String(nfl.season_type || '');
  if (!season || !week || (type !== 'regular' && type !== 'post')) return { skipped: `season_type ${type || 'unknown'}` };
  const seasonWeek = `${season}-${type === 'post' ? 'p' : ''}${week}`;

  const stats = await getJson(`${SLEEPER}/stats/nfl/${type}/${season}/${week}`);
  const present = new Set(Object.keys(stats || {}));
  const next = E.countsFromStats(stats);
  const st = await loadState();

  // New week (or first ever run): baseline only.
  if (!st || String(st.season) !== season || +st.week !== week || st.counts == null) {
    await saveState({ season, week, counts: next, pending: {}, revs: {}, last_live_at: st && st.last_live_at });
    return { baseline: seasonWeek, players: Object.keys(next).length };
  }

  const prev = st.counts || {};
  const { ups, downs } = E.diffCounts(prev, next, present);
  const revs = { ...(st.revs || {}) };
  for (const e of ups) e.rev = revs[`${e.sid}:${e.cat}`] || 0;
  for (const d of downs) d.rev = revs[`${d.sid}:${d.cat}`] || 0;

  // Reversals must show up on two polls in a row before we call a TD back.
  const pending = st.pending || {};
  const confirmed = [];
  // New state: this poll's counts for every player present in it; players missing
  // from this poll keep their last-known counts.
  const ZERO = { p: 0, r: 0, c: 0, o: 0 };
  const counts = {};
  for (const sid of new Set([...Object.keys(prev), ...Object.keys(next)])) {
    counts[sid] = present.has(sid) ? { ...(next[sid] || ZERO) } : { ...prev[sid] };
  }
  const nextPending = {};
  for (const d of downs) {
    const k = `${d.sid}:${d.cat}:${d.from}`;
    if (pending[k]) {
      confirmed.push(d); // second sighting → confirmed; counts take the lower value
      revs[`${d.sid}:${d.cat}`] = (d.rev || 0) + 1;
    } else {
      nextPending[k] = Date.now();
      counts[d.sid] = { ...(counts[d.sid] || ZERO), [d.cat]: d.from }; // hold old value until confirmed
    }
  }
  for (const sid in counts) { const c = counts[sid]; if (!(c.p || c.r || c.c || c.o)) delete counts[sid]; }

  await saveState({ season, week, counts, pending: nextPending, revs, last_live_at: st.last_live_at });

  if (ups.length) await sendTds(ups, season, week, seasonWeek);
  if (confirmed.length) await sendCalledBack(confirmed, season, week, seasonWeek);
  return { seasonWeek, ups: ups.length, calledBack: confirmed.length, pendingReversals: Object.keys(nextPending).length };
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const secret = process.env.CRON_SECRET;
  if (!secret || req.headers.authorization !== `Bearer ${secret}`) {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }
  if (!A.accountsConfigured() || !W.pushConfigured()) {
    res.status(200).json({ skipped: 'push not configured' });
    return;
  }
  const t0 = Date.now();
  try {
    // Only poll while a game is on (or within 30 min of the last live game, for
    // late stat changes). If ESPN can't be reached, poll anyway.
    const live = await anyGameLive();
    const st = await loadState().catch(() => null);
    const lastLive = st && st.last_live_at ? Date.parse(st.last_live_at) : 0;
    if (live === true) {
      await A.sbFetch(`push_td_state?id=eq.${STATE_ID}`, {
        method: 'PATCH', headers: { Prefer: 'return=minimal' },
        body: JSON.stringify({ last_live_at: new Date().toISOString() })
      }).catch(() => {});
    }
    if (live === false && Date.now() - lastLive > 30 * 60000) {
      res.status(200).json({ skipped: 'no live games' });
      return;
    }
    const out = [await pollOnce()];
    const wait = POLL_GAP_MS - (Date.now() - t0);
    if (wait > 0 && wait <= POLL_GAP_MS) {
      await new Promise((r) => setTimeout(r, wait));
      out.push(await pollOnce());
    }
    res.status(200).json({ polls: out });
  } catch (e) {
    console.error('td cron error:', e.message);
    await O.reportError(e, { req, where: 'push:td' });
    res.status(500).json({ error: e.message });
  }
};

module.exports = require('../_lib/observe').wrap(module.exports, 'push:td');
module.exports._test = { pollOnce };
