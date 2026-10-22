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
//   • building the payload for public.stats_replace_user_week (db/lineup-history.sql)

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
// disabled leagues, like the app and the alerts.
async function readAccountWeek(uid, season, week, platforms) {
  const fns = { sleeper: R.readSleeper, espn: R.readEspn, yahoo: R.readYahoo };
  const want = (platforms || []).filter((p) => fns[p]);
  const [results, disabled] = await Promise.all([
    Promise.all(want.map((p) => fns[p](uid, season, week).then(
      (rows) => ({ p, rows: rows || [], ok: !(rows && rows.failed > 0) }),
      (e) => { console.error('snapshot read failed', p, uid, e.message); return { p, rows: [], ok: false }; }
    ))),
    A.getDisabledLeagues(uid).catch(() => [])
  ]);
  const off = new Set(disabled || []);
  return {
    matchups: results.flatMap((r) => r.rows).filter((m) => !off.has(m.key)),
    okPlatforms: results.filter((r) => r.ok).map((r) => r.p),
    failedPlatforms: results.filter((r) => !r.ok).map((r) => r.p)
  };
}

const r2 = (v) => Math.round((+v || 0) * 100) / 100;

function buildPayload({ uid, season, week, matchups, okPlatforms, attempts }, idx) {
  const weeks = [], players = [], seen = new Set();
  for (const m of matchups || []) {
    if (!m || !m.platform || !m.leagueId) continue;
    const my = r2(m.myPts), opp = r2(m.oppPts);
    weeks.push({
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
  return { season: +season, week: +week, user_id: uid, attempts: attempts || 1, platforms: okPlatforms || [], weeks, players };
}

module.exports = { normTeam, unifiedPlayerKey, buildIndex, identify, readAccountWeek, buildPayload };
