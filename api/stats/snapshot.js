// api/stats/snapshot.js
// Weekly lineup history (Vercel Cron, hourly — see vercel.json). Once an NFL week
// is final, saves every connected account's starting lineups for that week — both
// sides of each matchup, with points and the result — into lineup_weeks /
// lineup_players (db/lineup-history.sql). Read server-side from Sleeper / ESPN /
// Yahoo with each account's saved connections (api/_lib/league-reader.js), so it
// never depends on the app being open. Feeds the private `stats` views.
//
// Self-scheduling backlog: every run works through (account, week) pairs that
// aren't captured yet, newest week first, until its time budget runs out:
//   • every final week of the season → the first runs after deploy backfill
//     Weeks 1..N, and a new account's earlier weeks fill in on its own
//   • an account that connects another platform later gets that platform's
//     past weeks filled in (the log records which platforms were read cleanly)
//   • a failed read (expired token, API error) is retried, up to MAX_ATTEMPTS,
//     or again whenever that connection is refreshed
// Nothing pending → a cheap no-op. "Final" = every game of the week is over and
// SETTLE_MS has passed since its last kickoff, so platform points have landed.
//
// Optional ?week=N re-reads that week for every account (ignores the log).
// Auth: Vercel Cron's "Authorization: Bearer $CRON_SECRET"; fails closed.

const A = require('../_lib/accounts');
const R = require('../_lib/league-reader');
const S = require('../_lib/status-alerts');
const L = require('../_lib/lineup-snapshot');
const O = require('../_lib/observe');

const REG_WEEKS = 18;
const SETTLE_MS = 10 * 3600e3;   // MNF kickoff 8:15pm ET → eligible ~6:15am ET Tuesday
const BUDGET_MS = 240e3;         // stop starting new reads after this (maxDuration 300)
const CONCURRENCY = 3;
const MAX_ATTEMPTS = 3;
const PLATFORMS = new Set(['sleeper', 'espn', 'yahoo']);

// PostgREST caps responses (1000 rows by default) — page through.
async function sbAll(path) {
  const out = [];
  for (let off = 0; ; off += 1000) {
    const rows = (await A.sbFetch(`${path}${path.includes('?') ? '&' : '?'}limit=1000&offset=${off}`)) || [];
    out.push(...rows);
    if (rows.length < 1000) return out;
  }
}

async function settled(season, week, now) {
  const g = await S.weekGames(season, week, 'regular');
  const evs = g.events.filter((e) => Number.isFinite(e.ms));
  if (!evs.length || !evs.every((e) => e.state === 'post')) return false;
  return now - Math.max(...evs.map((e) => e.ms)) >= SETTLE_MS;
}

// → { season, last } (last = newest final week, 0 = none yet) or null outside the season.
async function finalWeeks(now) {
  const ns = await S.nflState();
  if (!ns.season || !ns.week) return null;
  const season = +ns.season;
  if (ns.type === 'post') return { season, last: REG_WEEKS };
  if (ns.type !== 'regular') return null;
  for (let w = Math.min(ns.week, REG_WEEKS); w >= 1 && w >= ns.week - 1; w--) {
    if (await settled(ns.season, w, now)) return { season, last: w };
  }
  return { season, last: Math.max(0, ns.week - 2) };
}

// Connected accounts → Map(uid → Map(platform → updated_at ms)).
async function connectedAccounts() {
  const rows = await sbAll('platform_sessions?select=user_id,platform,updated_at&order=user_id,platform');
  const m = new Map();
  rows.forEach((r) => {
    if (!PLATFORMS.has(r.platform)) return;
    if (!m.has(r.user_id)) m.set(r.user_id, new Map());
    m.get(r.user_id).set(r.platform, Date.parse(r.updated_at) || 0);
  });
  return m;
}

function pendingPairs(season, last, accounts, logs, forceWeek) {
  const byKey = new Map(logs.map((l) => [`${l.week}|${l.user_id}`, l]));
  const out = [];
  const weeks = forceWeek ? [forceWeek] : Array.from({ length: last }, (_, i) => last - i); // newest first
  for (const week of weeks) {
    for (const [uid, plats] of accounts) {
      const log = byKey.get(`${week}|${uid}`);
      const prev = (log && log.platforms) || [];
      if (forceWeek || !log) { out.push({ uid, week, attempts: 1, platforms: [...plats.keys()], prev }); continue; }
      const have = new Set(prev);
      const missing = [...plats.keys()].filter((p) => !have.has(p));
      if (!missing.length) continue;
      const loggedAt = Date.parse(log.updated_at) || 0;
      const refreshed = missing.some((p) => plats.get(p) > loggedAt); // reconnected / token refreshed since
      if (log.attempts >= MAX_ATTEMPTS && !refreshed) continue;
      out.push({ uid, week, attempts: refreshed ? 1 : (log.attempts || 0) + 1, platforms: [...plats.keys()], prev });
    }
  }
  return out;
}

// Keeps the platforms already captured for this account-week (their rows stay).
async function logFailure(season, pair, message) {
  await A.sbFetch('lineup_snapshot_log?on_conflict=season,week,user_id', {
    method: 'POST', headers: { Prefer: 'resolution=merge-duplicates,return=minimal' },
    body: JSON.stringify([{ season, week: pair.week, user_id: pair.uid, status: 'error', leagues: 0, platforms: pair.prev || [], attempts: pair.attempts, error: String(message || '').slice(0, 300), updated_at: new Date().toISOString() }])
  }).catch((e) => console.error('snapshot log write failed', e.message));
}

async function capture(season, pair, idx) {
  const read = await L.readAccountWeek(pair.uid, season, pair.week, pair.platforms);
  // Logged platforms = every platform captured cleanly for this account-week so far.
  const captured = [...new Set([...(pair.prev || []), ...read.okPlatforms])];
  const payload = L.buildPayload({ uid: pair.uid, season, week: pair.week, matchups: read.matchups, okPlatforms: captured, attempts: pair.attempts }, idx);
  if (!payload.weeks.length && !read.okPlatforms.length) { await logFailure(season, pair, `read failed: ${read.failedPlatforms.join(',')}`); return 'failed'; }
  const r = await A.sbFetch('rpc/stats_replace_user_week', { method: 'POST', body: JSON.stringify({ p: payload }) });
  if (read.failedPlatforms.length) return 'partial';
  return r && r.leagues > 0 ? 'ok' : 'empty';
}

async function run(now, opts) {
  const fw = await finalWeeks(now);
  if (!fw) return { skipped: 'not in season' };
  const forceWeek = opts.week && opts.week >= 1 && opts.week <= REG_WEEKS ? opts.week : 0;
  if (!fw.last && !forceWeek) return { skipped: 'no final week yet', season: fw.season };
  const [accounts, logs] = await Promise.all([
    connectedAccounts(),
    sbAll(`lineup_snapshot_log?season=eq.${fw.season}&select=week,user_id,status,platforms,attempts,updated_at&order=week,user_id`)
  ]);
  const queue = pendingPairs(fw.season, fw.last, accounts, logs, forceWeek);
  const counts = { ok: 0, empty: 0, partial: 0, failed: 0 };
  if (!queue.length) return { season: fw.season, lastFinal: fw.last, pending: 0, ...counts };
  const idx = L.buildIndex(await R.sleeperPlayers());
  const total = queue.length;
  async function worker() {
    while (queue.length && Date.now() - now < BUDGET_MS) {
      const pair = queue.shift();
      try { counts[await capture(fw.season, pair, idx)]++; }
      catch (e) { counts.failed++; console.error('snapshot capture failed', pair.uid, pair.week, e.message); await logFailure(fw.season, pair, e.message); }
    }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  return { season: fw.season, lastFinal: fw.last, pending: total, processed: total - queue.length, remaining: queue.length, ...counts, ms: Date.now() - now };
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const secret = process.env.CRON_SECRET;
  if (!secret || req.headers.authorization !== `Bearer ${secret}`) { res.status(401).json({ error: 'unauthorized' }); return; }
  if (!A.accountsConfigured()) { res.status(200).json({ skipped: 'accounts not configured' }); return; }
  try {
    const week = parseInt((req.query && req.query.week) || '', 10) || 0;
    res.status(200).json(await run(Date.now(), { week }));
  } catch (e) {
    console.error('stats snapshot error:', e.message);
    await O.reportError(e, { req, where: 'stats:snapshot' });
    res.status(500).json({ error: e.message });
  }
};

module.exports = require('../_lib/observe').wrap(module.exports, 'stats:snapshot');
module.exports._test = { pendingPairs, finalWeeks, run };
