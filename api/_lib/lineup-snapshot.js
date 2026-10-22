// api/_lib/lineup-snapshot.js
// Pure-ish helpers for the weekly lineup history (api/stats/snapshot.js):
//   • canonical player identity, server-side — same rules as the app's
//     canonicalPlayerKey (index.html): DEF → 'DST|<team>', Sleeper id → 'sl:<id>',
//     else teamless 'name||POS'. ESPN / Yahoo players are mapped to a Sleeper id
//     first through the Sleeper DB's own espn_id / yahoo_id fields, then through the
//     app's two-tier name lookup (strict name|team|pos, then name|pos preferring an
//     active player). Team is never part of a skill player's identity.
//   • reading one account-week from every connected platform, with platform-level
//     failures reported (league-reader swallows them for the alerts)
//   • building the payload for public.stats_replace_user_week (db/lineup-history.sql),
//     with team names and league formats when the read carried opts.meta
//     (db/lineup-stats-v3.sql)
//   • pregame projections per matchup for public.matchup_projections

const A = require('./accounts');
const R = require('./league-reader');

const TEAM_ALIAS = { WSH: 'WAS', JAC: 'JAX', LA: 'LAR', OAK: 'LV', SD: 'LAC', STL: 'LAR' };
function normTeam(t) { const T = String(t || '').toUpperCase(); return TEAM_ALIAS[T] || T; }
function isDefPos(pos) { const P = String(pos || '').toUpperCase(); return P === 'DEF' || P === 'DST' || P === 'D/ST'; }

// index.html unifiedPlayerKey, verbatim rules.
function unifiedPlayerKey(name, team, pos) {
  const P = String(pos || '').toUpperCase(); const T = normTeam(team);
  if (P === 'DEF' || P === 'DST') return T ? 'DST|' + T : null;
  if (!name) return null;
  let N = String(name).toLowerCase();
  N = N.replace(/[.'`,]/g, '').replace(/-/g, ' ').replace(/\s+(jr|sr|ii|iii|iv|v)\.?\b/g, '').replace(/\s+/g, ' ').trim();
  return N + '|' + T + '|' + P;
}
function lastName(name) {
  const k = unifiedPlayerKey(name, '', 'X'); if (!k) return '';
  const n = k.split('|')[0].split(' '); return n[n.length - 1];
}

let IDX = null, IDX_DB = null;
function buildIndex(db) {
  if (IDX && IDX_DB === db) return IDX;
  const espn = new Map(), yahoo = new Map(), strict = new Map(), namePos = new Map(), namePosActive = new Map();
  const active = (info) => info.active === true || !!info.team;
  const putId = (map, id, pid, info) => {
    if (id == null || id === '') return;
    const k = String(id); const prev = map.get(k);
    if (!prev || (active(info) && !active(db[prev] || {}))) map.set(k, pid);
  };
  for (const pid of Object.keys(db || {})) {
    const info = db[pid]; if (!info || !/^\d+$/.test(pid)) continue;
    putId(espn, info.espn_id, pid, info);
    putId(yahoo, info.yahoo_id, pid, info);
    if (!info.full_name) continue;
    const k = unifiedPlayerKey(info.full_name, info.team || '', info.position || '');
    if (k && !strict.has(k)) strict.set(k, pid);
    const k2 = unifiedPlayerKey(info.full_name, '', info.position || '');
    if (k2 && (!namePos.has(k2) || (active(info) && !namePosActive.get(k2)))) { namePos.set(k2, pid); namePosActive.set(k2, active(info)); }
  }
  IDX = { db, espn, yahoo, strict, namePos }; IDX_DB = db;
  return IDX;
}

// → { key, sid } for one reader player P = { name, pos, team, pid }.
function identify(p, platform, idx) {
  const pos = String(p.pos || '').toUpperCase();
  if (isDefPos(pos)) {
    const T = normTeam(p.team || (platform === 'sleeper' ? p.pid : '') || '');
    return { key: T ? 'DST|' + T : `${platform}:${p.pid || p.name || '?'}`, sid: null };
  }
  const pid = String(p.pid || '');
  if (platform === 'sleeper' && /^\d+$/.test(pid)) return { key: 'sl:' + pid, sid: pid };
  // Platform id → Sleeper id, accepted only when the surnames agree (guards bad mappings).
  const viaId = platform === 'espn' ? idx.espn.get(pid) : platform === 'yahoo' ? idx.yahoo.get(pid) : null;
  if (viaId) {
    const info = idx.db[viaId] || {};
    if (!p.name || !info.full_name || lastName(info.full_name) === lastName(p.name)) return { key: 'sl:' + viaId, sid: viaId };
  }
  const segs = pos ? pos.split(',').map((x) => x.trim()).filter(Boolean) : [''];
  for (const seg of segs) {
    const k1 = unifiedPlayerKey(p.name, p.team || '', seg);
    const k2 = unifiedPlayerKey(p.name, '', seg);
    const hit = (k1 && idx.strict.get(k1)) || (k2 && idx.namePos.get(k2));
    if (hit) return { key: 'sl:' + hit, sid: hit };
  }
  const fallback = unifiedPlayerKey(p.name, '', segs[0] || '');
  return { key: fallback || `${platform}:${pid || '?'}`, sid: null };
}

// Every connected platform for one account-week. Unlike readAccountMatchups,
// reports which platforms were read cleanly (`okPlatforms`) — a platform with a
// failed read (expired token, API error, any league that threw) is left out, so
// the snapshot job tries that account-week again later. Respects the account's
// disabled leagues, like the app and the alerts. opts go to the readers (meta / lite /
// knownSettings — see league-reader.js).
async function readAccountWeek(uid, season, week, platforms, opts) {
  const fns = { sleeper: R.readSleeper, espn: R.readEspn, yahoo: R.readYahoo };
  const want = (platforms || []).filter((p) => fns[p]);
  const [results, disabled] = await Promise.all([
    Promise.all(want.map((p) => fns[p](uid, season, week, opts).then(
      (rows) => ({ p, rows: rows || [], ok: !(rows && rows.failed > 0), err: rows && rows.failed > 0 ? 'api' : null }),
      (e) => {
        console.error('snapshot read failed', p, uid, e.message);
        // 'token' = this account's connection (expired / refresh failed); 'api' = the platform itself.
        return { p, rows: [], ok: false, err: /token unavailable/.test(e.message) ? 'token' : 'api' };
      }
    ))),
    A.getDisabledLeagues(uid).catch(() => [])
  ]);
  const off = new Set(disabled || []);
  return {
    matchups: results.flatMap((r) => r.rows).filter((m) => !off.has(m.key)),
    okPlatforms: results.filter((r) => r.ok).map((r) => r.p),
    failedPlatforms: results.filter((r) => !r.ok).map((r) => r.p),
    errors: Object.fromEntries(results.filter((r) => !r.ok).map((r) => [r.p, r.err]))
  };
}

const r2 = (v) => Math.round((+v || 0) * 100) / 100;

// ── Pregame projections (public.matchup_projections) ────────────────────────
// Each platform's own projection, as the app shows it before kickoff:
//   • Yahoo: the scoreboard's team projection.
//   • ESPN: the sum of the starters' ESPN projections; a starter ESPN has none for
//     falls back to Sleeper's projection in the league's reception scoring.
//   • Sleeper: Sleeper's projected stat lines scored with the league's own
//     scoring_settings (the app's scoreProjectionStats, verbatim).
// A side with no projection for any starter is null, never 0.
const SLEEPER = 'https://api.sleeper.app/v1';
const PROJ = new Map(); // `${season}|${week}` → { at, data }
async function sleeperProjections(season, week) {
  const k = `${season}|${week}`, hit = PROJ.get(k);
  if (hit && Date.now() - hit.at < 30 * 60e3) return hit.data;
  const r = await fetch(`${SLEEPER}/projections/nfl/regular/${season}/${week}`, { headers: { Accept: 'application/json' } });
  if (!r.ok) throw new Error(`sleeper projections ${r.status}`);
  const j = await r.json();
  // Keyed by player id (as the app reads it); tolerate an array of { player_id, stats }.
  const data = {};
  if (Array.isArray(j)) j.forEach((x) => { if (x && x.player_id != null) data[String(x.player_id)] = x.stats || x; });
  else if (j && typeof j === 'object') Object.keys(j).forEach((id) => { data[id] = j[id]; });
  PROJ.set(k, { at: Date.now(), data });
  return data;
}
const FG_BAND_DIST = { fgm_0_19: 10, fgm_20_29: 25, fgm_30_39: 35, fgm_40_49: 45, fgm_50_59: 55, fgm_50p: 53, fgm_60p: 63 };
function scoreProjection(statObj, scoring) {
  if (!statObj || !scoring) return 0;
  const s = (statObj.stats && typeof statObj.stats === 'object') ? statObj.stats : statObj;
  let t = 0;
  for (const k in scoring) {
    if (k === 'fgm_yds' || k === 'fgm_yds_over_30') continue; // FG yardage handled via distance bands below
    const v = s[k];
    if (typeof v === 'number') t += v * scoring[k];
  }
  const rY = scoring.fgm_yds || 0, rO = scoring.fgm_yds_over_30 || 0;
  if (rY || rO) {
    for (const b in FG_BAND_DIST) {
      const makes = s[b];
      if (typeof makes !== 'number' || !makes) continue;
      const d = FG_BAND_DIST[b];
      if (rY) t += makes * d * rY;
      if (rO) t += makes * Math.max(0, d - 30) * rO;
    }
  }
  return t;
}
function ptsField(rec) { return rec == null || rec >= 0.75 ? 'pts_ppr' : rec >= 0.25 ? 'pts_half_ppr' : 'pts_std'; }

// → { my, opp } for one matchup read with opts.meta.
function matchupProjection(m, proj, idx) {
  const meta = m.meta || {};
  if (m.platform === 'yahoo') return { my: meta.myProjTeam != null ? r2(meta.myProjTeam) : null, opp: m.hasOpp && meta.oppProjTeam != null ? r2(meta.oppProjTeam) : null };
  const rec = meta.settings ? meta.settings.rec : null;
  const side = (list) => {
    let t = 0, any = false;
    for (const p of list || []) {
      let v = m.platform === 'espn' && p.proj != null ? +p.proj : null;
      if (v == null && proj) {
        let sid = null;
        if (m.platform === 'sleeper') sid = p.pid;
        else { const id = identify(p, m.platform, idx); sid = id.sid || (id.key.startsWith('DST|') ? id.key.slice(4) : null); }
        const st = sid ? proj[sid] : null;
        if (st) {
          if (m.platform === 'sleeper' && meta.scoring) v = scoreProjection(st, meta.scoring);
          else { const s = st.stats && typeof st.stats === 'object' ? st.stats : st; const f = s[ptsField(rec)]; v = typeof f === 'number' ? f : (typeof s.pts_ppr === 'number' ? s.pts_ppr : null); }
        }
      }
      if (v != null && Number.isFinite(v)) { t += v; any = true; }
    }
    return any ? r2(t) : null;
  };
  return { my: side(m.mine), opp: m.hasOpp ? side(m.opp) : null };
}

// Rows for public.matchup_projections from one account's read of an upcoming week.
function projectionRows({ uid, season, week, matchups }, proj, idx) {
  const out = [], seen = new Set();
  for (const m of matchups || []) {
    if (!m || !m.platform || !m.leagueId || !m.meta || seen.has(`${m.platform}|${m.leagueId}`)) continue;
    seen.add(`${m.platform}|${m.leagueId}`);
    const pr = matchupProjection(m, proj, idx);
    if (pr.my == null && pr.opp == null) continue;
    const teams = m.meta.teams || {};
    out.push({
      season: +season, week: +week, user_id: uid, platform: m.platform, league_id: String(m.leagueId),
      team_id: m.teamId != null ? String(m.teamId) : null, opp_team_id: m.hasOpp && m.oppTeamId != null ? String(m.oppTeamId) : null,
      team_name: (m.teamId != null && teams[String(m.teamId)]) || null,
      opp_team_name: (m.hasOpp && m.oppTeamId != null && teams[String(m.oppTeamId)]) || null,
      my_proj: pr.my, opp_proj: pr.opp, captured_at: new Date().toISOString()
    });
  }
  return out;
}

// League format + every team's name, per league, for public.stats_save_league_meta.
function leagueMeta(matchups) {
  const out = [], seen = new Set();
  for (const m of matchups || []) {
    if (!m || !m.meta || !m.platform || !m.leagueId || seen.has(`${m.platform}|${m.leagueId}`)) continue;
    seen.add(`${m.platform}|${m.leagueId}`);
    out.push({ platform: m.platform, league_id: String(m.leagueId), settings: m.meta.settings || null, teams: m.meta.teams || {} });
  }
  return out;
}

// ── NFL schedule for the game-day stats (public.nfl_games) ──────────────────
// Slot by Eastern kickoff: THU / FRI / SAT, Sunday SUN_EARLY (before 3pm ET, incl.
// London), SUN_LATE (3–7pm), SNF (7pm on), MNF (Monday), OTHER (Tue/Wed specials).
function slotFor(ms) {
  const o = {};
  new Intl.DateTimeFormat('en-US', { timeZone: 'America/New_York', weekday: 'short', hour: '2-digit', hourCycle: 'h23' })
    .formatToParts(new Date(ms)).forEach((x) => { o[x.type] = x.value; });
  const h = +o.hour;
  switch (o.weekday) {
    case 'Thu': return 'THU';
    case 'Fri': return 'FRI';
    case 'Sat': return 'SAT';
    case 'Mon': return 'MNF';
    case 'Sun': return h < 15 ? 'SUN_EARLY' : h < 19 ? 'SUN_LATE' : 'SNF';
    default: return 'OTHER';
  }
}
const SCOREBOARD = 'https://site.api.espn.com/apis/site/v2/sports/football/nfl/scoreboard';
// → [{ season, week, home, away, kickoff, slot, label, state }] (regular season)
async function fetchWeekSchedule(season, week) {
  const r = await fetch(`${SCOREBOARD}?dates=${season}&seasontype=2&week=${week}`, { headers: { Accept: 'application/json' } });
  if (!r.ok) throw new Error(`scoreboard ${r.status}`);
  const j = await r.json();
  const out = [];
  for (const e of j.events || []) {
    const comp = e.competitions && e.competitions[0]; if (!comp) continue;
    const side = { home: null, away: null }, nick = { home: '', away: '' };
    for (const c of comp.competitors || []) {
      if (c.homeAway !== 'home' && c.homeAway !== 'away') continue;
      side[c.homeAway] = normTeam(c.team && c.team.abbreviation);
      nick[c.homeAway] = (c.team && (c.team.name || c.team.shortDisplayName)) || side[c.homeAway] || '';
    }
    const ms = Date.parse(e.date);
    if (!side.home || !side.away || !Number.isFinite(ms)) continue;
    out.push({
      season: +season, week: +week, home: side.home, away: side.away,
      kickoff: new Date(ms).toISOString(), slot: slotFor(ms),
      label: `${nick.away}\u2013${nick.home}`,
      state: (comp.status && comp.status.type && comp.status.type.state) || ''
    });
  }
  return out;
}

// metaPlatforms = the platforms read cleanly in THIS read (recorded in league_meta_log).
function buildPayload({ uid, season, week, matchups, okPlatforms, attempts, metaPlatforms }, idx) {
  const weeks = [], players = [], seen = new Set();
  for (const m of matchups || []) {
    if (!m || !m.platform || !m.leagueId) continue;
    const my = r2(m.myPts), opp = r2(m.oppPts);
    const tn = (m.meta && m.meta.teams) || {};
    weeks.push({
      team_name: (m.teamId != null && tn[String(m.teamId)]) || null,
      opp_team_name: (m.hasOpp && m.oppTeamId != null && tn[String(m.oppTeamId)]) || null,
      platform: m.platform, league_id: String(m.leagueId), league_name: m.key ? m.key.slice(m.platform.length + 1) : m.name,
      team_id: m.teamId != null ? String(m.teamId) : null,
      opp_team_id: m.hasOpp && m.oppTeamId != null ? String(m.oppTeamId) : null,
      has_opp: !!m.hasOpp, my_pts: my, opp_pts: m.hasOpp ? opp : null,
      result: m.hasOpp ? (my > opp ? 'W' : my < opp ? 'L' : 'T') : null,
      starters: (m.mine || []).length
    });
    [['mine', m.mine], ['opp', m.hasOpp ? m.opp : []]].forEach(([side, list]) => {
      (list || []).forEach((p) => {
        if (!p) return;
        const id = identify(p, m.platform, idx);
        const dedupe = `${m.platform}|${m.leagueId}|${side}|${id.key}`;
        if (seen.has(dedupe)) return; seen.add(dedupe);
        players.push({
          platform: m.platform, league_id: String(m.leagueId), side, player_key: id.key, sleeper_id: id.sid,
          platform_player_id: p.pid ? String(p.pid) : null,
          name: p.name || null, pos: String(p.pos || '').toUpperCase() || null, team: normTeam(p.team) || null, pts: r2(p.pts)
        });
      });
    });
  }
  const out = { season: +season, week: +week, user_id: uid, attempts: attempts || 1, platforms: okPlatforms || [], weeks, players };
  // A read with opts.meta: league formats + team names go along (stats_save_league_meta).
  if (Array.isArray(metaPlatforms)) { out.leagues = leagueMeta(matchups); out.meta_platforms = metaPlatforms; }
  return out;
}

module.exports = {
  normTeam, unifiedPlayerKey, buildIndex, identify, readAccountWeek, buildPayload, slotFor, fetchWeekSchedule,
  sleeperProjections, scoreProjection, matchupProjection, projectionRows, leagueMeta
};
