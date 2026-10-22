// api/_lib/league-reader.js
// Server-side reader for one account's matchups in a given week, straight from
// Sleeper / ESPN / Yahoo using the connections saved to the account — so status
// alerts use the REAL current lineups and never depend on the app being open.
//
// Returns [{ key, name, platform, myPts, oppPts, hasOpp, mine:[P], opp:[P],
//            leagueId, teamId, oppTeamId }]
//   P = { name, pos, team, pts, inj, pid } for each STARTER (inj = raw injury/status
//   string from the platform, '' when healthy; pid = the platform's own player id —
//   the Sleeper id on Sleeper, which is what the lineup-history snapshot keys on).
//   leagueId / teamId / oppTeamId are the platform's own ids (Sleeper league_id +
//   roster_id, ESPN league id + team id, Yahoo league_key + team_key), same formats
//   as league_connections. Additive — the alert builders ignore them.
//   bench:[P] = MY bench only (not IR / taxi slots) — used by the first-game
//   lineup alert to count every player of yours in a game, starters + bench.
// key = "platform|rawLeagueName" — the same key the app uses for the per-league
// on/off switches (Settings → League connections), which are respected here.
// Parsing mirrors the app's provider code (index.html) so numbers agree:
//   • ESPN live totals = sum of starters' appliedTotal (schedule totalPoints sits at
//     0 during play), bench = lineup slots 20/21.
//   • Yahoo: scoreboard team points; starters = selected_position not BN/IR;
//     never-drafted ('predraft') leagues and empty shells are skipped.
//   • Sleeper: matchup points + starters, taxi excluded on the opponent side.
//
// opts (optional 4th argument; the alerts pass none, so nothing changes for them):
//   meta: true → each matchup also carries m.meta = {
//       settings: { teams, rec, teRec, passTd, qb, sf, flex, starters, idp, bestBall } | null,
//       teams:    { <team id>: <team name> } for EVERY team in the league,
//       scoring:  Sleeper's raw scoring_settings (to score projections) | null,
//       myProjTeam / oppProjTeam: Yahoo's own pregame team projections | null }
//     Extra calls: Sleeper +1 per league (/users); ESPN none (settings and teams are
//     already in the read); Yahoo +1 per league for settings, skipped for leagues in
//     opts.knownSettings (a Set of 'yahoo|<league_key>').
//   lite: true → Yahoo skips the two roster calls per league (for projection and
//     name reads that only need the scoreboard).
// ESPN starters always carry P.proj = ESPN's own projection for the week (null if none).

const A = require('./accounts');

const SLEEPER = 'https://api.sleeper.app/v1';
const UA = 'Mozilla/5.0 (compatible; ConflictedFantasy/1.0; +https://www.conflictedapp.com)';

const ESPN_PRO_TEAMS = { 0: 'FA', 1: 'ATL', 2: 'BUF', 3: 'CHI', 4: 'CIN', 5: 'CLE', 6: 'DAL', 7: 'DEN', 8: 'DET', 9: 'GB', 10: 'TEN', 11: 'IND', 12: 'KC', 13: 'LV', 14: 'LAR', 15: 'MIA', 16: 'MIN', 17: 'NE', 18: 'NO', 19: 'NYG', 20: 'NYJ', 21: 'PHI', 22: 'ARI', 23: 'PIT', 24: 'LAC', 25: 'SF', 26: 'SEA', 27: 'TB', 28: 'WAS', 29: 'CAR', 30: 'JAX', 33: 'BAL', 34: 'HOU' };
const ESPN_POSITIONS = { 1: 'QB', 2: 'RB', 3: 'WR', 4: 'TE', 5: 'K', 7: 'P', 9: 'DT', 10: 'DE', 11: 'LB', 12: 'CB', 13: 'S', 14: 'HC', 16: 'DEF' };
const ESPN_BENCH_SLOTS = new Set([20, 21]);

async function getJson(url, opts) {
  const r = await fetch(url, opts || { headers: { Accept: 'application/json' } });
  if (!r.ok) { const e = new Error(`${new URL(url).hostname} ${r.status}`); e.status = r.status; throw e; }
  return r.json();
}

/* ── League format (opts.meta) ────────────────────────────────────────────── */
// One shape for all three platforms. rec = points per reception, teRec = extra per
// TE reception (TE premium), passTd = points per passing TD; qb / sf / flex = starting
// QB, superflex and flex slots; starters = every starting slot; idp = individual
// defensive players start; bestBall = lineups set automatically.
const num = (v) => (v == null || v === '' || !Number.isFinite(+v) ? null : +v);
const IDP_SLOTS = new Set(['DL', 'LB', 'DB', 'IDP_FLEX', 'DE', 'DT', 'CB', 'S', 'SS', 'FS', 'D']);

function sleeperSettings(lg) {
  const s = lg.scoring_settings, rp = Array.isArray(lg.roster_positions) ? lg.roster_positions.map(String) : [];
  const st = rp.filter((p) => p !== 'BN' && p !== 'IR' && p !== 'TAXI');
  const cnt = (f) => st.filter(f).length;
  return {
    teams: num(lg.total_rosters),
    rec: s ? num(s.rec) || 0 : null, teRec: s ? num(s.bonus_rec_te) || 0 : null, passTd: s ? num(s.pass_td) : null,
    qb: rp.length ? cnt((p) => p === 'QB') : null, sf: rp.length ? cnt((p) => p === 'SUPER_FLEX') : null,
    flex: rp.length ? cnt((p) => /FLEX/.test(p) && p !== 'SUPER_FLEX' && p !== 'IDP_FLEX') : null,
    starters: rp.length ? st.length : null, idp: st.some((p) => IDP_SLOTS.has(p)),
    bestBall: !!(lg.settings && +lg.settings.best_ball === 1)
  };
}

// ESPN: scoring statId 53 = reception, 4 = passing TD (pointsOverrides keyed by lineup
// slot; 6 = TE). Lineup slots: 0 QB, 7 OP (superflex), 3 RB/WR, 5 WR/TE, 23 FLEX,
// 8–15 IDP, 20 bench, 21 IR.
function espnSettings(data) {
  const st = (data && data.settings) || {}, sc = st.scoringSettings || {}, rs = st.rosterSettings || {};
  const items = Array.isArray(sc.scoringItems) ? sc.scoringItems : null;
  const item = (id) => (items || []).find((x) => +x.statId === id);
  const rec = item(53), ptd = item(4);
  const slots = rs.lineupSlotCounts && typeof rs.lineupSlotCounts === 'object' ? rs.lineupSlotCounts : null;
  const c = (k) => (slots ? +slots[k] || 0 : 0);
  const recPts = rec ? num(rec.points) || 0 : (items ? 0 : null);
  const teOver = rec && rec.pointsOverrides && rec.pointsOverrides['6'] != null ? num(rec.pointsOverrides['6']) : null;
  return {
    teams: num(st.size) || (Array.isArray(data.teams) ? data.teams.length : null),
    rec: recPts, teRec: teOver != null && recPts != null ? Math.max(0, teOver - recPts) : (items ? 0 : null),
    passTd: ptd ? num(ptd.points) : null,
    qb: slots ? c('0') : null, sf: slots ? c('7') : null, flex: slots ? c('3') + c('5') + c('23') : null,
    starters: slots ? Object.keys(slots).filter((k) => k !== '20' && k !== '21').reduce((t, k) => t + c(k), 0) : null,
    idp: slots ? ['8', '9', '10', '11', '12', '13', '14', '15'].some((k) => c(k) > 0) : false,
    bestBall: false
  };
}
function espnTeamName(t) {
  return t ? (t.name || [t.location, t.nickname].filter(Boolean).join(' ').trim() || t.abbrev || null) : null;
}

// Yahoo: stat 11 = reception, 5 = passing TD; roster position 'Q/W/R/T' = superflex.
// The settings JSON nests differently league to league, so search it by key.
function yhFind(o, key, depth = 0) {
  if (!o || typeof o !== 'object' || depth > 8) return undefined;
  if (Object.prototype.hasOwnProperty.call(o, key)) return o[key];
  for (const k of Object.keys(o)) { const v = yhFind(o[k], key, depth + 1); if (v !== undefined) return v; }
  return undefined;
}
function yhList(node, inner) {
  const out = [];
  const visit = (x) => {
    if (!x || typeof x !== 'object') return;
    if (x[inner]) { out.push(Array.isArray(x[inner]) ? yhFlatten(x[inner]) : x[inner]); return; }
    (Array.isArray(x) ? x : Object.values(x)).forEach(visit);
  };
  visit(node);
  return out;
}
function yhSettings(json, numTeams) {
  const lg = json && json.fantasy_content && json.fantasy_content.league;
  const pos = yhList(yhFind(lg, 'roster_positions'), 'roster_position')
    .map((r) => ({ p: String(r.position || ''), n: +r.count || 0 }))
    .filter((r) => r.p && r.p !== 'BN' && r.p !== 'IR');
  const mods = yhList(yhFind(lg, 'stat_modifiers'), 'stat');
  const mod = (id) => { const m = mods.find((x) => String(x.stat_id) === String(id)); return m ? num(m.value) : null; };
  const n = (f) => pos.filter(f).reduce((t, r) => t + r.n, 0);
  const meta = Array.isArray(lg) ? yhFlatten(lg[0]) : {};
  return {
    teams: num(numTeams) || num(meta.num_teams),
    rec: mods.length ? mod(11) || 0 : null, teRec: mods.length ? 0 : null, passTd: mod(5),
    qb: pos.length ? n((r) => r.p === 'QB') : null, sf: pos.length ? n((r) => r.p === 'Q/W/R/T') : null,
    flex: pos.length ? n((r) => /^[WRT](\/[WRT])+$/.test(r.p)) : null,
    starters: pos.length ? n(() => true) : null, idp: pos.some((r) => IDP_SLOTS.has(r.p)),
    bestBall: false
  };
}

/* ── Sleeper ──────────────────────────────────────────────────────────────── */
let PLAYER_DB = null, PLAYER_DB_AT = 0; // ~5MB, cached for the life of the warm function
async function sleeperPlayers() {
  if (PLAYER_DB && Date.now() - PLAYER_DB_AT < 6 * 3600e3) return PLAYER_DB;
  PLAYER_DB = await getJson(`${SLEEPER}/players/nfl`);
  PLAYER_DB_AT = Date.now();
  return PLAYER_DB;
}
function sleeperP(id, pp, db) {
  const info = db[id] || {};
  const isDef = !info.position && String(id).length <= 4;
  return {
    name: info.full_name || [info.first_name, info.last_name].filter(Boolean).join(' ') || (isDef ? id : ''),
    pos: String(info.position || (isDef ? 'DEF' : '')).toUpperCase(),
    team: String(info.team || (isDef ? id : '')).toUpperCase(),
    pts: +((pp || {})[id]) || 0,
    inj: String(info.injury_status || ''),
    pid: String(id)
  };
}
async function readSleeper(uid, season, week, opts) {
  const meta = !!(opts && opts.meta);
  const blob = await A.getPlatformSession(uid, 'sleeper');
  if (!blob) return [];
  let username = null;
  try { username = JSON.parse(A.decrypt(blob)).u || null; } catch (e) { return []; }
  if (!username) return [];
  const user = await getJson(`${SLEEPER}/user/${encodeURIComponent(username)}`);
  if (!user || !user.user_id) return [];
  const leagues = (await getJson(`${SLEEPER}/user/${user.user_id}/leagues/nfl/${season}`)) || [];
  if (!leagues.length) return [];
  const db = await sleeperPlayers();
  const out = [];
  out.failed = 0; // leagues whose read threw (lineup-history snapshot retries those)
  await Promise.all(leagues.map(async (lg) => {
    try {
      const [rosters, matchups, users] = await Promise.all([
        getJson(`${SLEEPER}/league/${lg.league_id}/rosters`),
        getJson(`${SLEEPER}/league/${lg.league_id}/matchups/${week}`),
        meta ? getJson(`${SLEEPER}/league/${lg.league_id}/users`).catch(() => null) : Promise.resolve(null) // names are optional
      ]);
      const mineR = (rosters || []).find((r) => r.owner_id === user.user_id || (Array.isArray(r.co_owners) && r.co_owners.includes(user.user_id)));
      if (!mineR) return;
      const me = (matchups || []).find((m) => m.roster_id === mineR.roster_id);
      if (!me) return;
      const op = me.matchup_id != null ? (matchups || []).find((m) => m.matchup_id === me.matchup_id && m.roster_id !== mineR.roster_id) : null;
      const oppR = op ? (rosters || []).find((r) => r.roster_id === op.roster_id) : null;
      const taxi = new Set(((oppR && oppR.taxi) || []).filter(Boolean));
      const clean = (a) => (a || []).filter((id) => id && id !== '0');
      let ms = clean(me.starters); if (!ms.length) ms = clean(mineR.starters);
      let os = op ? clean(op.starters).filter((id) => !taxi.has(id)) : [];
      const msSet = new Set(ms), myHold = new Set([...((mineR.reserve) || []), ...((mineR.taxi) || [])].filter(Boolean));
      const bench = clean(me.players && me.players.length ? me.players : mineR.players).filter((id) => !msSet.has(id) && !myHold.has(id));
      if (op && !os.length && oppR) os = clean(oppR.starters).filter((id) => !taxi.has(id));
      const m = {
        key: `sleeper|${lg.name}`, name: lg.name, platform: 'sleeper',
        leagueId: String(lg.league_id), teamId: String(mineR.roster_id), oppTeamId: op ? String(op.roster_id) : null,
        myPts: +me.points || 0, oppPts: op ? (+op.points || 0) : 0,
        hasOpp: !!(op && os.length),
        mine: ms.map((id) => sleeperP(id, me.players_points, db)),
        opp: os.map((id) => sleeperP(id, op && op.players_points, db)),
        bench: bench.map((id) => sleeperP(id, me.players_points, db))
      };
      if (meta) {
        // A team's name is its manager's team_name, else the manager's display name (what Sleeper shows).
        const byUser = {};
        (Array.isArray(users) ? users : []).forEach((u) => { if (u && u.user_id) byUser[u.user_id] = (u.metadata && u.metadata.team_name) || u.display_name || null; });
        const teams = {};
        (rosters || []).forEach((r) => { if (r && r.roster_id != null) teams[String(r.roster_id)] = (r.owner_id && byUser[r.owner_id]) || null; });
        m.meta = { settings: sleeperSettings(lg), teams, scoring: lg.scoring_settings || null, myProjTeam: null, oppProjTeam: null };
      }
      out.push(m);
    } catch (e) { out.failed++; console.error('reader sleeper league failed', lg.league_id, e.message); }
  }));
  return out;
}

/* ── ESPN ─────────────────────────────────────────────────────────────────── */
function espnStat(entry, week, src) {
  const stats = (entry && entry.playerPoolEntry && entry.playerPoolEntry.player && entry.playerPoolEntry.player.stats) || [];
  const s = stats.find((x) => x.scoringPeriodId === week && x.statSourceId === src);
  return s ? Number(s.appliedTotal || 0) : null;
}
function espnP(entry, week) {
  const p = (entry && entry.playerPoolEntry && entry.playerPoolEntry.player) || {};
  return {
    name: p.fullName || `${p.firstName || ''} ${p.lastName || ''}`.trim(),
    pos: ESPN_POSITIONS[p.defaultPositionId] || '',
    team: ESPN_PRO_TEAMS[p.proTeamId] || '',
    pts: espnStat(entry, week, 0) || 0,
    inj: String(p.injuryStatus || (entry && entry.injuryStatus) || ''),
    pid: String(p.id != null ? p.id : (entry && entry.playerId != null ? entry.playerId : '')),
    proj: espnStat(entry, week, 1) // ESPN's own projection for the week (statSourceId 1), null if none
  };
}
async function readEspn(uid, season, week, opts) {
  const meta = !!(opts && opts.meta);
  const blob = await A.getPlatformSession(uid, 'espn');
  if (!blob) return [];
  let s;
  try { s = JSON.parse(A.decrypt(blob)); } catch (e) { return []; }
  const lids = Array.isArray(s.lids) && s.lids.length ? s.lids.map(String) : (s.lid ? [String(s.lid)] : []);
  const swid = String(s.sw || '').toLowerCase();
  const out = [];
  out.failed = 0;
  await Promise.all(lids.map(async (lid) => {
    try {
      const qs = ['mBoxscore', 'mMatchupScore', 'mTeam', 'mRoster', 'mSettings'].map((v) => `view=${v}`).join('&');
      const url = `https://lm-api-reads.fantasy.espn.com/apis/v3/games/ffl/seasons/${season}/segments/0/leagues/${encodeURIComponent(lid)}?${qs}&scoringPeriodId=${week}`;
      const data = await getJson(url, { headers: { Cookie: `espn_s2=${s.s2}; SWID=${s.sw}`, 'User-Agent': UA, Accept: 'application/json' } });
      if (data.seasonId != null && String(data.seasonId) !== String(season)) return; // carried-over league
      const myTeam = (data.teams || []).find((t) => (t.owners || []).some((o) => String(o).toLowerCase() === swid));
      if (!myTeam) return;
      const mu = (data.schedule || []).find((x) => x.matchupPeriodId === week && ((x.home && x.home.teamId === myTeam.id) || (x.away && x.away.teamId === myTeam.id)));
      if (!mu) return;
      const isHome = mu.home && mu.home.teamId === myTeam.id;
      const meE = isHome ? mu.home : mu.away, opE = isHome ? mu.away : mu.home;
      const starters = (side) => ((side && side.rosterForCurrentScoringPeriod && side.rosterForCurrentScoringPeriod.entries) || [])
        .filter((e) => !ESPN_BENCH_SLOTS.has(e.lineupSlotId));
      const mine = starters(meE).map((e) => espnP(e, week));
      const bench = ((meE && meE.rosterForCurrentScoringPeriod && meE.rosterForCurrentScoringPeriod.entries) || [])
        .filter((e) => e.lineupSlotId === 20).map((e) => espnP(e, week)); // 21 = IR
      const opp = starters(opE).map((e) => espnP(e, week));
      const sum = (arr) => +arr.reduce((t, p) => t + (+p.pts || 0), 0).toFixed(2);
      const name = (data.settings && data.settings.name) || `ESPN league ${lid}`;
      const m = {
        key: `espn|${name}`, name, platform: 'espn',
        leagueId: String(lid), teamId: String(myTeam.id), oppTeamId: opE && opE.teamId != null ? String(opE.teamId) : null,
        myPts: mine.length ? sum(mine) : (+meE.totalPoints || 0),
        oppPts: opp.length ? sum(opp) : (+(opE && opE.totalPoints) || 0),
        hasOpp: !!(opE && opE.teamId != null && opp.length), mine, opp, bench
      };
      if (meta) {
        const teams = {};
        (data.teams || []).forEach((t) => { if (t && t.id != null) teams[String(t.id)] = espnTeamName(t); });
        m.meta = { settings: espnSettings(data), teams, scoring: null, myProjTeam: null, oppProjTeam: null };
      }
      out.push(m);
    } catch (e) { out.failed++; console.error('reader espn league failed', lid, e.message); }
  }));
  return out;
}

/* ── Yahoo ────────────────────────────────────────────────────────────────── */
function yhEach(obj, fn) { if (!obj || typeof obj !== 'object') return; Object.keys(obj).forEach((k) => { if (/^\d+$/.test(k)) fn(obj[k], k); }); }
function yhFlatten(arr) {
  if (!arr) return {};
  if (!Array.isArray(arr)) return (typeof arr === 'object') ? { ...arr } : {};
  const out = {};
  arr.forEach((item) => { if (Array.isArray(item)) Object.assign(out, yhFlatten(item)); else if (item && typeof item === 'object') Object.assign(out, item); });
  return out;
}
function yhLeagues(json, season) {
  const out = []; const users = json && json.fantasy_content && json.fantasy_content.users; if (!users) return out;
  yhEach(users, (u) => {
    const games = u && u.user && u.user[1] && u.user[1].games; if (!games) return;
    yhEach(games, (g) => {
      const game = g && g.game; const meta = Array.isArray(game) ? yhFlatten(game[0]) : {};
      const ln = Array.isArray(game) ? game[1] && game[1].leagues : null; if (!ln) return;
      yhEach(ln, (lw) => {
        const lArr = lw && lw.league; if (!lArr) return;
        const lm = Array.isArray(lArr) ? yhFlatten(lArr[0]) : lArr;
        if (lm.game_code && lm.game_code !== 'nfl') return;
        if (String(lm.season || meta.season || '') !== String(season)) return;
        out.push({ league_key: lm.league_key, name: lm.name, draft_status: lm.draft_status || '', num_teams: lm.num_teams != null ? +lm.num_teams : null });
      });
    });
  });
  return out;
}
function yhMyTeamKey(json) {
  const leagueArr = json && json.fantasy_content && json.fantasy_content.league;
  const st = Array.isArray(leagueArr) ? ((leagueArr[1] && leagueArr[1].standings && leagueArr[1].standings[0] && leagueArr[1].standings[0].teams) || (leagueArr[1] && leagueArr[1].standings && leagueArr[1].standings.teams)) : null;
  let key = null;
  yhEach(st, (tw) => {
    const tArr = tw && tw.team; if (!Array.isArray(tArr) || key) return;
    const meta = yhFlatten(tArr[0]);
    let mine = meta.is_owned_by_current_login === 1 || meta.is_owned_by_current_login === '1';
    if (Array.isArray(meta.managers)) meta.managers.forEach((mw) => { const m = mw && mw.manager; if (m && (m.is_current_login === '1' || m.is_current_login === 1)) mine = true; });
    if (mine) key = meta.team_key;
  });
  return key;
}
function yhScoreboard(json) {
  const out = []; const leagueArr = json && json.fantasy_content && json.fantasy_content.league;
  const sb = Array.isArray(leagueArr) ? leagueArr[1] && leagueArr[1].scoreboard : null;
  const matchups = (sb && sb['0'] && sb['0'].matchups) || (sb && sb.matchups); if (!matchups) return out;
  yhEach(matchups, (mw) => {
    const m = mw && mw.matchup; if (!m) return;
    const teamsNode = (m['0'] && m['0'].teams) || m.teams; const teams = [];
    yhEach(teamsNode, (tw) => {
      const tArr = tw && tw.team; if (!Array.isArray(tArr)) return;
      const meta = yhFlatten(tArr[0]);
      const ex = Array.isArray(tArr[1]) ? yhFlatten(tArr[1]) : (tArr[1] || {});
      const proj = parseFloat((ex.team_projected_points || {}).total);
      teams.push({ team_key: meta.team_key, points: parseFloat((ex.team_points || {}).total) || 0, name: meta.name || null, proj: Number.isFinite(proj) ? proj : null });
    });
    out.push({ status: m.status || '', teams });
  });
  return out;
}
function yhRoster(json) {
  const out = []; const teamArr = json && json.fantasy_content && json.fantasy_content.team;
  const rn = Array.isArray(teamArr) ? teamArr[1] && teamArr[1].roster : null;
  const players = (rn && rn['0'] && rn['0'].players) || (rn && rn.players); if (!players) return out;
  yhEach(players, (pw) => {
    const pArr = pw && pw.player; if (!Array.isArray(pArr)) return;
    const meta = yhFlatten(pArr[0]);
    let sp = {}, pts = null;
    for (let i = 1; i < pArr.length; i++) {
      const sib = pArr[i]; if (!sib) continue;
      const cands = Array.isArray(sib) ? sib : [sib];
      for (const c of cands) {
        if (c && c.selected_position && !sp.position) sp = yhFlatten(c.selected_position);
        if (c && c.player_points && pts == null) pts = parseFloat(c.player_points.total) || 0;
      }
    }
    const slot = sp.position || '';
    out.push({
      starter: !!slot && slot !== 'BN' && slot !== 'IR',
      slot,
      inj: String(meta.status || ''),
      name: (meta.name && meta.name.full) || '',
      pos: String(meta.display_position || meta.primary_position || '').toUpperCase(),
      team: String(meta.editorial_team_abbr || '').toUpperCase(),
      pts: pts || 0,
      pid: String(meta.player_id || '')
    });
  });
  return out;
}
async function yahooToken(uid) {
  const blob = await A.getPlatformSession(uid, 'yahoo');
  if (!blob) return null;
  let s; try { s = JSON.parse(A.decrypt(blob)); } catch (e) { return null; }
  if (Math.floor(Date.now() / 1000) < (s.exp || 0) - 60) return s.at;
  // Refresh + write the rotated token back to the account (same as api/yahoo/data.js).
  const basic = Buffer.from(`${process.env.YAHOO_CLIENT_ID}:${process.env.YAHOO_CLIENT_SECRET}`).toString('base64');
  const r = await fetch('https://api.login.yahoo.com/oauth2/get_token', {
    method: 'POST',
    headers: { Authorization: `Basic ${basic}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: s.rt, redirect_uri: process.env.YAHOO_REDIRECT_URI }).toString()
  });
  if (!r.ok) { console.error('reader yahoo refresh failed', r.status); return null; }
  const f = await r.json();
  const fresh = { at: f.access_token, rt: f.refresh_token || s.rt, exp: Math.floor(Date.now() / 1000) + (f.expires_in || 3600), guid: s.guid };
  try { await A.savePlatformSession(uid, 'yahoo', A.encrypt(JSON.stringify(fresh))); } catch (e) { console.error('reader yahoo writeback failed', e.message); }
  return fresh.at;
}
async function readYahoo(uid, season, week, opts) {
  const meta = !!(opts && opts.meta), lite = !!(opts && opts.lite);
  const known = (opts && opts.knownSettings) || new Set();
  const at = await yahooToken(uid);
  if (!at) {
    // Throw (not return []) so the lineup-history snapshot can tell "token refresh
    // failed" from "no leagues". readAccountMatchups catches it → [] exactly as before.
    if (await A.getPlatformSession(uid, 'yahoo')) throw new Error('yahoo token unavailable');
    return [];
  }
  const Y = 'https://fantasysports.yahooapis.com/fantasy/v2';
  const yget = (path) => getJson(`${Y}/${path}${path.includes('?') ? '&' : '?'}format=json`, { headers: { Authorization: `Bearer ${at}` } });
  const leagues = yhLeagues(await yget(`users;use_login=1/games;game_codes=nfl;seasons=${season}/leagues`), season)
    .filter((l) => l.draft_status !== 'predraft'); // never-drafted / moved leagues (app's dormant gate)
  const out = [];
  out.failed = 0;
  await Promise.all(leagues.map(async (lg) => {
    try {
      const myKey = yhMyTeamKey(await yget(`league/${encodeURIComponent(lg.league_key)}/standings`));
      if (!myKey) return;
      const board = yhScoreboard(await yget(`league/${encodeURIComponent(lg.league_key)}/scoreboard;week=${week}`));
      const mu = board.find((m) => m.teams.some((t) => t.team_key === myKey));
      if (!mu) return;
      const me = mu.teams.find((t) => t.team_key === myKey), op = mu.teams.find((t) => t.team_key !== myKey);
      const strip = ({ starter, slot, ...p }) => p;
      let mine = [], opp = [], bench = [];
      if (!lite) {
        const roster = async (k) => yhRoster(await yget(`team/${encodeURIComponent(k)}/roster;week=${week}/players/stats;type=week;week=${week}`));
        const [mineAll, oppAll] = await Promise.all([roster(myKey), op ? roster(op.team_key) : Promise.resolve([])]);
        if (!mineAll.length && (!op || !oppAll.length)) return; // empty shell (app's backstop)
        const st = (arr) => { const s = arr.filter((p) => p.starter); return (s.length ? s : arr).map(strip); };
        mine = st(mineAll); opp = st(oppAll);
        bench = mineAll.some((p) => p.starter) ? mineAll.filter((p) => !p.starter && p.slot === 'BN').map(strip) : [];
      }
      const m = {
        key: `yahoo|${lg.name}`, name: lg.name, platform: 'yahoo',
        leagueId: String(lg.league_key), teamId: String(myKey), oppTeamId: op ? String(op.team_key) : null,
        myPts: me.points, oppPts: op ? op.points : 0, hasOpp: !!(op && (lite || opp.length)), mine, opp, bench
      };
      if (meta) {
        const teams = {};
        board.forEach((x) => x.teams.forEach((t) => { if (t.team_key) teams[String(t.team_key)] = t.name || null; }));
        let settings = null;
        if (!known.has(`yahoo|${lg.league_key}`)) {
          // Settings are optional: a failed settings call leaves the format unknown for now.
          settings = await yget(`league/${encodeURIComponent(lg.league_key)}/settings`).then((j) => yhSettings(j, lg.num_teams), () => null);
        }
        m.meta = { settings, teams, scoring: null, myProjTeam: me.proj, oppProjTeam: op ? op.proj : null };
      }
      out.push(m);
    } catch (e) { out.failed++; console.error('reader yahoo league failed', lg.league_key, e.message); }
  }));
  return out;
}

/* ── All platforms ────────────────────────────────────────────────────────── */
async function readAccountMatchups(uid, season, week) {
  const [sl, es, yh, disabled] = await Promise.all([
    readSleeper(uid, season, week).catch((e) => { console.error('reader sleeper', e.message); return []; }),
    readEspn(uid, season, week).catch((e) => { console.error('reader espn', e.message); return []; }),
    readYahoo(uid, season, week).catch((e) => { console.error('reader yahoo', e.message); return []; }),
    A.getDisabledLeagues(uid).catch(() => [])
  ]);
  const off = new Set(disabled || []);
  const all = [...sl, ...es, ...yh].filter((m) => !off.has(m.key));
  // Same-named leagues on two platforms get a platform suffix, like the app.
  const LABEL = { sleeper: 'Sleeper', espn: 'ESPN', yahoo: 'Yahoo' };
  const count = {};
  all.forEach((m) => { count[m.name] = (count[m.name] || new Set()).add(m.platform); });
  all.forEach((m) => { if (count[m.name].size > 1) m.name = `${m.name} (${LABEL[m.platform]})`; });
  return all;
}

module.exports = { readAccountMatchups, sleeperPlayers, readSleeper, readEspn, readYahoo, yhLeagues, yhMyTeamKey, yhScoreboard, yhRoster, sleeperSettings, espnSettings, yhSettings };
