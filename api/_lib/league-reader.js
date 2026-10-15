// api/_lib/league-reader.js
// Server-side reader for one account's matchups in a given week, straight from
// Sleeper / ESPN / Yahoo using the connections saved to the account — so status
// alerts use the REAL current lineups and never depend on the app being open.
//
// Returns [{ key, name, platform, myPts, oppPts, hasOpp, mine:[P], opp:[P] }]
//   P = { name, pos, team, pts, inj } for each STARTER (inj = raw injury/status
//   string from the platform, '' when healthy).
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
    inj: String(info.injury_status || '')
  };
}
async function readSleeper(uid, season, week) {
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
  await Promise.all(leagues.map(async (lg) => {
    try {
      const [rosters, matchups] = await Promise.all([
        getJson(`${SLEEPER}/league/${lg.league_id}/rosters`),
        getJson(`${SLEEPER}/league/${lg.league_id}/matchups/${week}`)
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
      out.push({
        key: `sleeper|${lg.name}`, name: lg.name, platform: 'sleeper',
        myPts: +me.points || 0, oppPts: op ? (+op.points || 0) : 0,
        hasOpp: !!(op && os.length),
        mine: ms.map((id) => sleeperP(id, me.players_points, db)),
        opp: os.map((id) => sleeperP(id, op && op.players_points, db)),
        bench: bench.map((id) => sleeperP(id, me.players_points, db))
      });
    } catch (e) { console.error('reader sleeper league failed', lg.league_id, e.message); }
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
    inj: String(p.injuryStatus || (entry && entry.injuryStatus) || '')
  };
}
async function readEspn(uid, season, week) {
  const blob = await A.getPlatformSession(uid, 'espn');
  if (!blob) return [];
  let s;
  try { s = JSON.parse(A.decrypt(blob)); } catch (e) { return []; }
  const lids = Array.isArray(s.lids) && s.lids.length ? s.lids.map(String) : (s.lid ? [String(s.lid)] : []);
  const swid = String(s.sw || '').toLowerCase();
  const out = [];
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
      out.push({
        key: `espn|${name}`, name, platform: 'espn',
        myPts: mine.length ? sum(mine) : (+meE.totalPoints || 0),
        oppPts: opp.length ? sum(opp) : (+(opE && opE.totalPoints) || 0),
        hasOpp: !!(opE && opE.teamId != null && opp.length), mine, opp, bench
      });
    } catch (e) { console.error('reader espn league failed', lid, e.message); }
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
        out.push({ league_key: lm.league_key, name: lm.name, draft_status: lm.draft_status || '' });
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
      teams.push({ team_key: meta.team_key, points: parseFloat((ex.team_points || {}).total) || 0 });
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
      pts: pts || 0
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
async function readYahoo(uid, season, week) {
  const at = await yahooToken(uid);
  if (!at) return [];
  const Y = 'https://fantasysports.yahooapis.com/fantasy/v2';
  const yget = (path) => getJson(`${Y}/${path}${path.includes('?') ? '&' : '?'}format=json`, { headers: { Authorization: `Bearer ${at}` } });
  const leagues = yhLeagues(await yget(`users;use_login=1/games;game_codes=nfl;seasons=${season}/leagues`), season)
    .filter((l) => l.draft_status !== 'predraft'); // never-drafted / moved leagues (app's dormant gate)
  const out = [];
  await Promise.all(leagues.map(async (lg) => {
    try {
      const myKey = yhMyTeamKey(await yget(`league/${encodeURIComponent(lg.league_key)}/standings`));
      if (!myKey) return;
      const mu = yhScoreboard(await yget(`league/${encodeURIComponent(lg.league_key)}/scoreboard;week=${week}`))
        .find((m) => m.teams.some((t) => t.team_key === myKey));
      if (!mu) return;
      const me = mu.teams.find((t) => t.team_key === myKey), op = mu.teams.find((t) => t.team_key !== myKey);
      const roster = async (k) => yhRoster(await yget(`team/${encodeURIComponent(k)}/roster;week=${week}/players/stats;type=week;week=${week}`));
      const [mineAll, oppAll] = await Promise.all([roster(myKey), op ? roster(op.team_key) : Promise.resolve([])]);
      if (!mineAll.length && (!op || !oppAll.length)) return; // empty shell (app's backstop)
      const strip = ({ starter, slot, ...p }) => p;
      const st = (arr) => { const s = arr.filter((p) => p.starter); return (s.length ? s : arr).map(strip); };
      const mine = st(mineAll), opp = st(oppAll);
      const bench = mineAll.some((p) => p.starter) ? mineAll.filter((p) => !p.starter && p.slot === 'BN').map(strip) : [];
      out.push({
        key: `yahoo|${lg.name}`, name: lg.name, platform: 'yahoo',
        myPts: me.points, oppPts: op ? op.points : 0, hasOpp: !!(op && opp.length), mine, opp, bench
      });
    } catch (e) { console.error('reader yahoo league failed', lg.league_key, e.message); }
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

module.exports = { readAccountMatchups, readSleeper, readEspn, readYahoo, yhLeagues, yhMyTeamKey, yhScoreboard, yhRoster };
