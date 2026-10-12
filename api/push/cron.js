// api/push/cron.js
// Scheduled alert sender (Vercel Cron — see "crons" in vercel.json).
//
// Alert #1 — Sunday Lineup Check-In reminder (2026-10-11, Matt):
//   one hour before the FIRST Sunday kickoff at or after 11:00 ET, i.e. the main
//   1pm ET / noon CT slate. London games (9:30 ET) are deliberately skipped, so
//   nobody gets a 7:30am CT buzz for a game they may not have a player in.
//   Generic copy for v1 — no per-user league reads yet.
//
// The cron fires every 5 minutes on Sunday mornings (UTC). Each run:
//   1. finds that kickoff from ESPN's public scoreboard,
//   2. does nothing unless now is 15–62 minutes before it,
//   3. for every device with prefs.checkin on, claims a (device, 'checkin',
//      kickoff) row in push_sends FIRST — overlapping runs can't double-send —
//      then sends. Dead devices (404/410) are deleted.
//
// Security: Vercel sends "Authorization: Bearer $CRON_SECRET" on cron calls.
// Without CRON_SECRET set, this endpoint refuses to run (fails closed).

const A = require('../_lib/accounts');
const W = require('../_lib/webpush');
const O = require('../_lib/observe');

const CHECKIN_MESSAGE = {
  kind: 'checkin',
  title: 'One hour to kickoff.',
  body: "You've already checked your lineups this week. Check again anyway.",
  url: '/?checkin=1&push=checkin',
  tag: 'cf-checkin'
};

const SCOREBOARD = 'https://site.api.espn.com/apis/site/v2/sports/football/nfl/scoreboard';

// Eastern-time parts for a timestamp (DST-safe via Intl).
function etParts(ms) {
  const f = new Intl.DateTimeFormat('en-US', {
    timeZone: 'America/New_York', weekday: 'short', year: 'numeric', month: '2-digit',
    day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23'
  });
  const o = {};
  for (const p of f.formatToParts(new Date(ms))) o[p.type] = p.value;
  return { weekday: o.weekday, date: `${o.year}-${o.month}-${o.day}`, minutes: (+o.hour) * 60 + (+o.minute) };
}

// First kickoff today (ET), on a Sunday, at or after 11:00 ET. Pure — testable.
function mainSlateKickoff(eventDates, nowMs) {
  const today = etParts(nowMs);
  if (today.weekday !== 'Sun') return null;
  let best = null;
  for (const d of eventDates) {
    const ms = Date.parse(d);
    if (!Number.isFinite(ms)) continue;
    const p = etParts(ms);
    if (p.date !== today.date || p.minutes < 11 * 60) continue;
    if (best === null || ms < best) best = ms;
  }
  return best;
}

function inSendWindow(kickMs, nowMs) {
  const lead = kickMs - nowMs;
  return lead <= 62 * 60000 && lead >= 15 * 60000;
}

async function fetchEventDates() {
  const r = await fetch(`${SCOREBOARD}?_cb=${Date.now()}`, { headers: { Accept: 'application/json' } });
  if (!r.ok) throw new Error(`ESPN scoreboard ${r.status}`);
  const j = await r.json();
  return (j.events || []).map((e) => e && e.date).filter(Boolean);
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
  const r = await W.sendPush(sub, message, { ttl: 45 * 60 });
  const patch = r.ok
    ? { last_sent_at: new Date().toISOString(), fail_count: 0 }
    : { fail_count: (sub.fail_count || 0) + 1 };
  if (r.gone) {
    await A.sbFetch(`push_subscriptions?id=eq.${sub.id}`, { method: 'DELETE', headers: { Prefer: 'return=minimal' } }).catch(() => {});
  } else {
    await A.sbFetch(`push_subscriptions?id=eq.${sub.id}`, {
      method: 'PATCH', headers: { Prefer: 'return=minimal' }, body: JSON.stringify(patch)
    }).catch(() => {});
  }
  if (!r.ok) console.error('push send failed', sub.id, r.status, r.text);
  return r;
}

async function runCheckin(nowMs) {
  const kick = mainSlateKickoff(await fetchEventDates(), nowMs);
  if (!kick) return { checkin: 'no Sunday main-slate kickoff today' };
  if (!inSendWindow(kick, nowMs)) return { checkin: 'outside window', kickoff: new Date(kick).toISOString() };

  const key = new Date(kick).toISOString();
  const subs = await A.sbFetch(
    'push_subscriptions?select=id,endpoint,p256dh,auth,fail_count&prefs->>checkin=eq.true'
  ) || [];
  let sent = 0, failed = 0, skipped = 0;
  for (let i = 0; i < subs.length; i += 10) {
    await Promise.all(subs.slice(i, i + 10).map(async (sub) => {
      try {
        if (!(await claim(sub.id, 'checkin', key))) { skipped++; return; }
        const r = await deliver(sub, CHECKIN_MESSAGE);
        r.ok ? sent++ : failed++;
      } catch (e) {
        failed++;
        console.error('checkin send error', sub.id, e.message);
      }
    }));
  }
  return { checkin: 'sent', kickoff: key, devices: subs.length, sent, failed, skipped };
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
  try {
    const out = await runCheckin(Date.now());
    res.status(200).json(out);
  } catch (e) {
    console.error('push cron error:', e.message);
    await O.reportError(e, { req, where: 'push:cron' });
    res.status(500).json({ error: e.message });
  }
};

module.exports = require('../_lib/observe').wrap(module.exports, 'push:cron');
module.exports._test = { mainSlateKickoff, inSendWindow, etParts };
