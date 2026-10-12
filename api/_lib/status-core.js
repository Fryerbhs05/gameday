// api/_lib/status-core.js
// Pure logic for the Sunday-night status and Tuesday results alerts (no I/O).
//
// "Same logic as the Snapshot List view" (Matt, 2026-10-12): Won / Lost use the
// app's STRICT lock (cfMatchupLock, index.html) plus the Snapshot's terminal case
// (every starter's game final → decided by score). The in-play line uses the
// Snapshot's cardDetail + toGoTxt wording and thresholds verbatim (text-only:
// &mdash; → —, names joined "A, B & C"). api/_lib/status-core.test.js checks the
// lock constants and the to-go wording against index.html so the two can't drift.
//
// ONE deliberate difference: a starter whose team has NO game this week (a bye —
// i.e. his team is absent from a week scoreboard that loaded fine) counts as DONE
// with his points. The app counts an unknown team as still-to-play (safe on a
// live board, where a missing team usually means the scoreboard hasn't loaded);
// in an alert that would print a bye-week starter as "to go" all night.

const CF_FLOOR_DEF = -4;
const CF_FLOOR_PENALTY = { QB: -8, RB: -2, WR: -2, TE: -2, K: 0 };
const CF_FLOOR_PENALTY_DEFAULT = -2;
const LOTS_PER_SIDE = 4, NAME_TO_GO_MAX = 3;
const TEAM_ALIAS = { WSH: 'WAS', JAC: 'JAX', LA: 'LAR', OAK: 'LV', SD: 'LAC', STL: 'LAR' };

function normTeam(t) { const T = String(t || '').toUpperCase(); return TEAM_ALIAS[T] || T; }
function nf(v) { return (Math.round(v * 100) / 100).toFixed(2); }
function isDefPos(pos) { const P = String(pos || '').toUpperCase(); return P === 'DEF' || P === 'DST' || P === 'D/ST'; }
function floorPenaltyFor(pos) {
  const P = String(pos || '').toUpperCase();
  if (P.indexOf('QB') !== -1 || P.indexOf('Q/') === 0) return CF_FLOOR_PENALTY.QB;
  if (P === 'K' || P === 'PK') return CF_FLOOR_PENALTY.K;
  return CF_FLOOR_PENALTY_DEFAULT;
}

// games: { states: Map(normTeam -> 'pre'|'in'|'post'), loaded: bool }
function isDone(p, games) {
  const T = normTeam(p && p.team);
  if (!T) return false;
  const st = games.states.get(T);
  if (st === undefined) return !!games.loaded; // bye (see header) — unknown only when the slate failed to load
  return st === 'post';
}
function sideToGo(players, games) { return (players || []).filter((p) => !isDone(p, games)).length; }
function sideCeiling(players, total, games) {
  if (!players || !players.length) return Infinity;
  return sideToGo(players, games) > 0 ? Infinity : (+total || 0);
}
function sideFloor(players, total, games) {
  if (!players || !players.length) return -Infinity;
  let f = +total || 0;
  for (const p of players) {
    if (isDone(p, games)) continue;
    f += isDefPos(p.pos) ? (CF_FLOOR_DEF - (+p.pts || 0)) : floorPenaltyFor(p.pos);
  }
  return f;
}

function shortName(p) {
  const pos = String(p.pos || '').toUpperCase();
  if (pos === 'DEF' || pos === 'DST' || pos === 'D/ST') return String(p.team || p.name || '').toUpperCase();
  const n = String(p.name || '').trim(); if (!n) return '';
  const parts = n.split(/\s+/); return parts[parts.length - 1];
}
function names(arr) {
  if (arr.length <= 1) return arr.join('');
  return arr.slice(0, -1).join(', ') + ' & ' + arr[arr.length - 1];
}
// Snapshot toGoTxt, text version.
function toGoTxt(myList, myLeft, oppList, oppLeft) {
  if (myLeft > LOTS_PER_SIDE && oppLeft > LOTS_PER_SIDE) return ' — lots of game left.';
  const total = myLeft + oppLeft;
  if (myLeft > 0 && oppLeft > 0) {
    if (total <= NAME_TO_GO_MAX && myList.length === myLeft && oppList.length === oppLeft)
      return ' — ' + names(myList) + ' vs ' + names(oppList) + ' to go.';
    return ' — ' + myLeft + ' of yours and ' + oppLeft + ' of theirs to go.';
  }
  const n = myLeft || oppLeft, list = myLeft ? myList : oppList, who = myLeft ? 'yours' : 'theirs';
  if (total <= NAME_TO_GO_MAX && list.length === n) return ' — ' + names(list) + ' to go.';
  return ' — ' + n + ' of ' + who + ' to go.';
}

// One matchup → Snapshot-style row. m = { name, myPts, oppPts, mine:[{name,pos,team,pts}], opp:[…], hasOpp }
// final=true (Tuesday): every game is over, decide purely by score.
function buildRow(m, games, final) {
  const my = +m.myPts || 0, opp = +m.oppPts || 0;
  if (!m.hasOpp) return null; // NO_OPPONENT sits out, as on the Snapshot
  let state;
  if (final) state = my > opp ? 'cwin' : 'closs';
  else {
    const allPost = (m.mine.length + m.opp.length) > 0 && m.mine.concat(m.opp).every((p) => isDone(p, games));
    if (sideFloor(m.mine, my, games) > sideCeiling(m.opp, opp, games)) state = 'cwin';
    else if (sideFloor(m.opp, opp, games) > sideCeiling(m.mine, my, games)) state = 'closs';
    else if (allPost) state = my > opp ? 'cwin' : 'closs';
    else state = 'live';
  }
  const left = (list) => (final ? [] : list.filter((p) => !isDone(p, games)));
  const toGo = (list) => left(list).map(shortName).filter(Boolean).slice(0, 3);
  return {
    name: m.name, state, curMy: my, curOpp: opp,
    myLeft: left(m.mine).length, oppLeft: left(m.opp).length,
    myToGo: toGo(m.mine), oppToGo: toGo(m.opp)
  };
}

// Snapshot cardDetail (live branch), text version.
function detail(r) {
  const gap = r.curMy - r.curOpp;
  if (gap >= 0) return 'Up ' + nf(gap) + (r.oppLeft ? toGoTxt(r.myToGo, r.myLeft, r.oppToGo, r.oppLeft) : ' and pulling away.');
  return 'Chasing ' + nf(-gap) + (r.myLeft ? toGoTxt(r.myToGo, r.myLeft, r.oppToGo, r.oppLeft) : '.');
}

function countLines(rows) {
  const total = rows.length;
  const won = rows.filter((r) => r.state === 'cwin').length;
  const lost = rows.filter((r) => r.state === 'closs').length;
  const out = [];
  if (won) out.push(`${won} of ${total} matchups won.`);
  if (lost) out.push(`${lost} of ${total} matchups lost.`);
  return out;
}

// Sunday night: counts, then one line per matchup still in play.
// Order: ups first (smallest lead first = most at risk), then chases (smallest gap first).
function snfMessage(matchups, games) {
  const rows = matchups.map((m) => buildRow(m, games, false)).filter(Boolean);
  if (!rows.length) return null;
  const live = rows.filter((r) => r.state === 'live').sort((a, b) => {
    const ga = a.curMy - a.curOpp, gb = b.curMy - b.curOpp;
    if ((ga >= 0) !== (gb >= 0)) return ga >= 0 ? -1 : 1;
    return Math.abs(ga) - Math.abs(gb);
  });
  const lines = countLines(rows).concat(live.map((r) => `${r.name}: ${detail(r)}`));
  return { title: 'Sunday night is final.', body: lines.join('\n'), rows };
}

// Tuesday: counts, then every matchup's final.
function tuesdayMessage(matchups, week) {
  const rows = matchups.map((m) => buildRow(m, null, true)).filter(Boolean);
  if (!rows.length) return null;
  const ordered = rows.slice().sort((a, b) => (a.state === b.state ? 0 : a.state === 'cwin' ? -1 : 1));
  const lines = countLines(rows).concat(ordered.map((r) => {
    const res = r.curMy > r.curOpp ? 'Won' : r.curMy < r.curOpp ? 'Lost' : 'Tied';
    return `${r.name}: ${res} ${nf(r.curMy)} to ${nf(r.curOpp)}.`;
  }));
  return { title: `Week ${week} is final.`, body: lines.join('\n'), rows };
}

module.exports = {
  CF_FLOOR_DEF, CF_FLOOR_PENALTY, CF_FLOOR_PENALTY_DEFAULT, LOTS_PER_SIDE, NAME_TO_GO_MAX,
  normTeam, nf, isDone, buildRow, detail, toGoTxt, names, shortName, snfMessage, tuesdayMessage
};
