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
// Also saves each final week's NFL schedule (kickoff + ET slot) into nfl_games for
// the game-day stats, and rebuilds the stats schema's manager tables after writing.
//
// League formats, team names and projections (db/lineup-stats-v3.sql):
//   • every read also saves each league's format (reception scoring, superflex,
//     size…) to league_settings and every team's name to lineup_team_names
//   • accounts captured before that existed get one catch-up read of their newest
//     final week; the names fill in for all of their earlier weeks
//   • Thursday projections: from PROJ_LEAD_MS before the upcoming week's first
//     kickoff until that kickoff, each account's pregame projections per matchup are
//     saved to matchup_projections, refreshed every PROJ_REFRESH_MS
// Captures go first, then projections, then the catch-up reads, in one time budget.
//
// Yahoo guard: Yahoo rate-limits per app (HTTP 999), and the live app shares that
// quota. Each run reads Yahoo for at most YAHOO_PAIRS_PER_RUN account reads (all
// three kinds together) and stops reading Yahoo for the rest of the run after a
// Yahoo API failure (one account's expired token doesn't stop the others); deferred
// Yahoo reads don't count as attempts. (The first backfill tripped 999s.)
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
const YAHOO_PAIRS_PER_RUN = 10;
const PROJ_LEAD_MS = 36 * 3600e3;               // Thursday-night week → from Wednesday ~8am ET
const PROJ_REFRESH_MS = 12 * 3600e3 - 15 * 60e3; // hourly cron → refreshed on the 12th hour
const SETTINGS_TTL_MS = 7 * 86400e3;             // Yahoo settings re-read weekly (one extra call)
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
async function finalWeeks(now, nsIn) {
  const ns = nsIn || await S.nflState();
  if (!ns.season || !ns.week) return null;
  const season = +ns.season;
  if (ns.type === 'post') return { season, last: REG_WEEKS };
  if (ns.type !== 'regular') return null;
  for (let w = Math.min(ns.week, REG_WEEKS); w >= 1 && w >= ns.week - 1; w--) {
    if (await settled(ns.season, w, now)) return { season, last: w };
  }
  return { season, last: Math.max(0, ns.week - 2) };
}

// The upcoming week while its projections are being captured: from PROJ_LEAD_MS
// before its first kickoff until that kickoff. → { season, week, kickoff } or null.
async function projectionWeek(now, ns) {
  if (!ns || !ns.season || ns.type !== 'regular') return null;
  for (const w of [ns.week, ns.week + 1]) {
    if (w < 1 || w > REG_WEEKS) continue;
    const g = await S.weekGames(ns.season, w, 'regular');
    const ms = g.events.map((e) => e.ms).filter(Number.isFinite);
    if (!ms.length) continue;
    const first = Math.min(...ms);
    if (now >= first) continue;                 // already under way
    return now >= first - PROJ_LEAD_MS ? { season: +ns.season, week: w, kickoff: first } : null;
  }
  return null;
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
      const prevAttempts = (log && log.attempts) || 0;
      if (forceWeek || !log) { out.push({ uid, week, attempts: 1, prevAttempts, platforms: [...plats.keys()], prev }); continue; }
      const have = new Set(prev);
      const missing = [...plats.keys()].filter((p) => !have.has(p));
      if (!missing.length) continue;
      const loggedAt = Date.parse(log.updated_at) || 0;
      const refreshed = missing.some((p) => plats.get(p) > loggedAt); // reconnected / token refreshed since
      if (log.attempts >= MAX_ATTEMPTS && !refreshed) continue;
      out.push({ uid, week, attempts: refreshed ? 1 : prevAttempts + 1, prevAttempts: refreshed ? 0 : prevAttempts, platforms: [...plats.keys()], prev });
    }
  }
  return out;
}

// Accounts whose league formats / team names haven't been read for every connected
// platform yet (league_meta_log), with the same retry rules as the lineup log.
function pendingMeta(accounts, logs) {
  const byUser = new Map(logs.map((l) => [l.user_id, l]));
  const out = [];
  for (const [uid, plats] of accounts) {
    const log = byUser.get(uid);
    const have = new Set((log && log.platforms) || []);
    const missing = [...plats.keys()].filter((p) => !have.has(p));
    if (!missing.length) continue;
    const refreshed = !!log && missing.some((p) => plats.get(p) > (Date.parse(log.updated_at) || 0));
    if (log && log.attempts >= MAX_ATTEMPTS && !refreshed) continue;
    out.push({ uid, platforms: missing, attempts: log && !refreshed ? (log.attempts || 0) + 1 : 1, prevAttempts: log && !refreshed ? log.attempts || 0 : 0 });
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

// Final weeks 1..last that aren't in nfl_games yet (a week is stored only once
// every game is over, so a stored week never changes).
async function fillSchedule(season, last) {
  const have = new Set(((await A.sbFetch(`nfl_games?season=eq.${season}&select=week`)) || []).map((r) => +r.week));
  let weeks = 0, games = 0;
  for (let w = 1; w <= last; w++) {
    if (have.has(w)) continue;
    const rows = await L.fetchWeekSchedule(season, w).catch((e) => { console.error('schedule fetch failed', w, e.message); return null; });
    if (!rows || !rows.length || !rows.every((g) => g.state === 'post')) continue;
    await A.sbFetch('nfl_games?on_conflict=season,week,home', {
      method: 'POST', headers: { Prefer: 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify(rows.map(({ state, ...g }) => ({ ...g, updated_at: new Date().toISOString() })))
    });
    weeks++; games += rows.length;
  }
  return { weeks, games };
}

// Yahoo guard (see header) for one account read: → { platforms, deferred } where
// deferred = Yahoo was dropped from this read; null = skip the read this run.
// Captures drop Yahoo and keep the rest (the log retries the Yahoo part); projection
// and catch-up reads (strict) skip the whole account until a run with Yahoo budget,
// so an account never ends up "done" without its Yahoo leagues.
function yahooGate(platforms, needed, yahoo, strict) {
  if (!platforms.includes('yahoo')) return { platforms, deferred: false };
  if (yahoo.blocked || yahoo.left <= 0) {
    if (strict || (needed || platforms).every((p) => p === 'yahoo')) return null;
    return { platforms: platforms.filter((p) => p !== 'yahoo'), deferred: true };
  }
  yahoo.left--;
  return { platforms, deferred: false };
}

async function capture(season, pair, idx, yahoo, known) {
  const gate = yahooGate(pair.platforms, pair.platforms.filter((p) => !(pair.prev || []).includes(p)), yahoo);
  if (!gate) return 'deferred';
  const read = await L.readAccountWeek(pair.uid, season, pair.week, gate.platforms, { meta: true, knownSettings: known });
  if (read.errors.yahoo === 'api') yahoo.blocked = true; // rate limit / outage — not one account's expired token
  const attempts = gate.deferred ? pair.prevAttempts : pair.attempts;
  // Logged platforms = every platform captured cleanly for this account-week so far.
  const captured = [...new Set([...(pair.prev || []), ...read.okPlatforms])];
  const payload = L.buildPayload({ uid: pair.uid, season, week: pair.week, matchups: read.matchups, okPlatforms: captured, attempts, metaPlatforms: read.okPlatforms }, idx);
  if (!payload.weeks.length && !read.okPlatforms.length) { await logFailure(season, { ...pair, attempts }, `read failed: ${read.failedPlatforms.join(',')}`); return 'failed'; }
  const r = await A.sbFetch('rpc/stats_replace_user_week', { method: 'POST', body: JSON.stringify({ p: payload }) });
  if (read.failedPlatforms.length) return 'partial';
  return r && r.leagues > 0 ? 'ok' : 'empty';
}

// Upcoming week: one account's pregame projections (+ league formats and names).
async function project(pw, pair, idx, yahoo, known, projFor) {
  const gate = yahooGate(pair.platforms, null, yahoo, true);
  if (!gate) return 'deferred';
  const read = await L.readAccountWeek(pair.uid, pw.season, pw.week, pair.platforms, { meta: true, lite: true, knownSettings: known });
  if (read.errors.yahoo === 'api') yahoo.blocked = true;
  const rows = L.projectionRows({ uid: pair.uid, season: pw.season, week: pw.week, matchups: read.matchups }, await projFor(), idx);
  if (rows.length) {
    await A.sbFetch('matchup_projections?on_conflict=season,week,user_id,platform,league_id', {
      method: 'POST', headers: { Prefer: 'resolution=merge-duplicates,return=minimal' }, body: JSON.stringify(rows)
    });
  }
  if (read.okPlatforms.length) {
    await A.sbFetch('rpc/stats_save_league_meta', { method: 'POST', body: JSON.stringify({ p: { season: pw.season, user_id: pair.uid, leagues: L.leagueMeta(read.matchups), meta_platforms: read.okPlatforms, attempts: 1 } }) })
      .catch((e) => console.error('league meta save failed', pair.uid, e.message));
  }
  if (!rows.length) return read.failedPlatforms.length ? 'failed' : 'empty';
  return read.failedPlatforms.length ? 'partial' : 'ok';
}

// Catch-up read of league formats + team names for an account captured before v3.
async function backfillMeta(season, week, pair, yahoo, known) {
  if (!yahooGate(pair.platforms, null, yahoo, true)) return 'deferred';
  const read = await L.readAccountWeek(pair.uid, season, week, pair.platforms, { meta: true, lite: true, knownSettings: known });
  if (read.errors.yahoo === 'api') yahoo.blocked = true;
  await A.sbFetch('rpc/stats_save_league_meta', { method: 'POST', body: JSON.stringify({ p: { season, user_id: pair.uid, leagues: L.leagueMeta(read.matchups), meta_platforms: read.okPlatforms, attempts: pair.attempts } }) });
  if (!read.okPlatforms.length) return 'failed';
  return read.failedPlatforms.length ? 'partial' : 'ok';
}

// Runs fn over the queue with CONCURRENCY workers until the run's time budget is spent.
async function drain(queue, now, counts, fn, label) {
  async function worker() {
    while (queue.length && Date.now() - now < BUDGET_MS) {
      const item = queue.shift();
      try { const k = await fn(item); counts[k] = (counts[k] || 0) + 1; }
      catch (e) { counts.failed = (counts.failed || 0) + 1; console.error(`snapshot ${label} failed`, item.uid, e.message); }
    }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
}

async function knownSettings(season, now) {
  const rows = await sbAll(`league_settings?season=eq.${season}&select=platform,league_id,updated_at`).catch(() => []);
  return new Set(rows.filter((r) => now - (Date.parse(r.updated_at) || 0) < SETTINGS_TTL_MS).map((r) => `${r.platform}|${r.league_id}`));
}

async function run(now, opts) {
  const ns = await S.nflState();
  const fw = await finalWeeks(now, ns);
  if (!fw) return { skipped: 'not in season' };
  const forceWeek = opts.week && opts.week >= 1 && opts.week <= REG_WEEKS ? opts.week : 0;
  const pw = forceWeek ? null : await projectionWeek(now, ns);
  if (!fw.last && !forceWeek && !pw) return { skipped: 'no final week yet', season: fw.season };
  const [accounts, logs, known] = await Promise.all([
    connectedAccounts(),
    sbAll(`lineup_snapshot_log?season=eq.${fw.season}&select=week,user_id,status,platforms,attempts,updated_at&order=week,user_id`),
    knownSettings(fw.season, now)
  ]);
  const schedule = fw.last ? await fillSchedule(fw.season, fw.last).catch((e) => { console.error('schedule fill failed', e.message); return { weeks: 0, games: 0, error: e.message }; }) : { weeks: 0, games: 0 };
  const yahoo = { left: YAHOO_PAIRS_PER_RUN, blocked: false };
  let idx = null;
  const index = async () => idx || (idx = L.buildIndex(await R.sleeperPlayers()));

  // 1. Lineups for final weeks.
  const queue = fw.last || forceWeek ? pendingPairs(fw.season, fw.last, accounts, logs, forceWeek) : [];
  const counts = { ok: 0, empty: 0, partial: 0, failed: 0, deferred: 0 };
  const total = queue.length;
  if (queue.length) {
    const ix = await index();
    async function worker() {
      while (queue.length && Date.now() - now < BUDGET_MS) {
        const pair = queue.shift();
        try { counts[await capture(fw.season, pair, ix, yahoo, known)]++; }
        catch (e) { counts.failed++; console.error('snapshot capture failed', pair.uid, pair.week, e.message); await logFailure(fw.season, pair, e.message); }
      }
    }
    await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  }

  // 2. Projections for the upcoming week (Wednesday morning → Thursday kickoff).
  let projections = null;
  if (pw && Date.now() - now < BUDGET_MS) {
    // Missing table (db/lineup-stats-v3.sql not applied yet) → skip projections, keep capturing.
    const have = await sbAll(`matchup_projections?season=eq.${pw.season}&week=eq.${pw.week}&select=user_id,captured_at`).catch((e) => { console.error('projections read failed', e.message); return null; });
    if (have) {
      const latest = new Map();
      have.forEach((r) => latest.set(r.user_id, Math.max(latest.get(r.user_id) || 0, Date.parse(r.captured_at) || 0)));
      // Accounts whose every connection failed on the newest final week (and hasn't been
      // reconnected since) are left out, so a dead token doesn't eat the Yahoo budget hourly.
      const newest = new Map();
      logs.forEach((l) => { const c = newest.get(l.user_id); if (!c || l.week > c.week) newest.set(l.user_id, l); });
      const broken = (uid, plats) => {
        const l = newest.get(uid);
        return !!l && l.status === 'error' && l.attempts >= MAX_ATTEMPTS && ![...plats.values()].some((t) => t > (Date.parse(l.updated_at) || 0));
      };
      const due = [...accounts]
        .filter(([uid, plats]) => (now - (latest.get(uid) || 0) >= PROJ_REFRESH_MS
          || [...plats.values()].some((t) => t > (latest.get(uid) || 0))) // a connection added or refreshed since
          && !broken(uid, plats))
        .sort((a, b) => (latest.get(a[0]) || 0) - (latest.get(b[0]) || 0)) // never captured first
        .map(([uid, plats]) => ({ uid, platforms: [...plats.keys()] }));
      const pc = { ok: 0, partial: 0, empty: 0, failed: 0, deferred: 0 };
      const pending = due.length;
      if (due.length) {
        const ix = await index();
        let proj; const projFor = async () => (proj !== undefined ? proj : (proj = await L.sleeperProjections(pw.season, pw.week).catch((e) => { console.error('sleeper projections failed', e.message); return null; })));
        await drain(due, now, pc, (pair) => project(pw, pair, ix, yahoo, known, projFor), 'projection');
      }
      projections = { week: pw.week, kickoff: new Date(pw.kickoff).toISOString(), pending, remaining: due.length, ...pc };
    } else projections = { week: pw.week, error: 'projections table unavailable' };
  }

  // 3. Catch-up reads of league formats + team names (accounts captured before v3).
  let meta = null;
  const metaLogs = fw.last && Date.now() - now < BUDGET_MS
    ? await sbAll(`league_meta_log?season=eq.${fw.season}&select=user_id,platforms,attempts,updated_at`).catch((e) => { console.error('meta log read failed', e.message); return null; })
    : null;
  if (metaLogs) {
    const mq = pendingMeta(accounts, metaLogs);
    const mc = { ok: 0, partial: 0, failed: 0, deferred: 0 };
    const pending = mq.length;
    if (mq.length) await drain(mq, now, mc, (pair) => backfillMeta(fw.season, fw.last, pair, yahoo, known), 'meta');
    meta = { pending, remaining: mq.length, ...mc };
  }

  let refreshed = false;
  if (counts.ok + counts.empty + counts.partial > 0 || schedule.weeks > 0) {
    try { await A.sbFetch('rpc/stats_refresh', { method: 'POST', body: '{}' }); refreshed = true; }
    catch (e) { console.error('stats refresh failed', e.message); }
  }
  return { season: fw.season, lastFinal: fw.last, pending: total, processed: total - queue.length, remaining: queue.length, ...counts, schedule, projections, meta, yahooLeft: yahoo.left, refreshed, ms: Date.now() - now };
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
module.exports._test = { pendingPairs, pendingMeta, finalWeeks, projectionWeek, fillSchedule, run };
