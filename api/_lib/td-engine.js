// api/_lib/td-engine.js
// Pure logic for touchdown alerts (no I/O) — kept separate so it can be unit-tested.
//
// Matt's rules (2026-10-12):
//   • Alert on TDs by the user's CHEER and CONFLICTED players (Enemy-only TDs never alert).
//   • Informative only: the TD, the leagues it helps, the leagues it hurts.
//     NO points (platform points trail stats; a TD's base value without its
//     yardage would mislead), NO yardage (two quick plays can merge between
//     polls), and NO verdict on how to feel (that needs real scoring + matchup
//     context the alert doesn't have).
//   • A TD pass to a receiver is ONE alert ("Jalen Hurts to A.J. Brown, TD").

const CAT_ORDER = ['c', 'r', 'o', 'p']; // receiver first, so a merged play is tagged by its receiver

function n(v) { return typeof v === 'number' && isFinite(v) ? v : 0; }
function isDefSid(sid) { return /^[A-Z]{2,3}$/.test(String(sid)); }

// TD counts for one Sleeper /stats row. p=passing r=rushing c=receiving o=other
// (returns, fumble-recovery TDs; for a team DEF: defensive + special-teams TDs).
function tdCounts(sid, row) {
  if (!row) return null;
  if (isDefSid(sid)) {
    const st = row.def_st_td != null ? n(row.def_st_td) : n(row.st_td);
    return { p: 0, r: 0, c: 0, o: n(row.def_td) + st };
  }
  return {
    p: n(row.pass_td),
    r: n(row.rush_td),
    c: n(row.rec_td),
    o: n(row.pr_td) + n(row.kr_td) + n(row.fum_rec_td)
  };
}

// { sid: {p,r,c,o} } for every player with at least one TD.
function countsFromStats(stats) {
  const out = {};
  for (const sid in stats || {}) {
    const c = tdCounts(sid, stats[sid]);
    if (c && (c.p || c.r || c.c || c.o)) out[sid] = c;
  }
  return out;
}

// Compare last-seen counts with this poll. A player whose row is missing from
// this poll is UNKNOWN (never treated as a drop). Drops are only candidates:
// the caller confirms them on a second poll before calling a TD back.
function diffCounts(prev, next, present) {
  const ups = [], downs = [];
  const sids = new Set([...Object.keys(prev || {}), ...Object.keys(next || {})]);
  for (const sid of sids) {
    if (!present.has(sid)) continue;
    const a = (prev && prev[sid]) || { p: 0, r: 0, c: 0, o: 0 };
    const b = (next && next[sid]) || { p: 0, r: 0, c: 0, o: 0 };
    for (const cat of CAT_ORDER) {
      if (b[cat] > a[cat]) ups.push({ sid, cat, from: a[cat], to: b[cat] });
      else if (b[cat] < a[cat]) downs.push({ sid, cat, from: a[cat], to: b[cat] });
    }
  }
  return { ups, downs };
}

function listJoin(names) {
  const a = names.slice();
  if (a.length > 4) { const more = a.length - 3; return a.slice(0, 3).join(', ') + ' and ' + more + ' more'; }
  if (a.length <= 1) return a.join('');
  return a.slice(0, -1).join(', ') + ' and ' + a[a.length - 1];
}

function displayName(p) {
  if (!p) return 'Your player';
  if (isDefSid(p.sid) || /^(DEF|DST|D\/ST)$/i.test(p.pos || '')) return (p.team || p.sid) + ' D/ST';
  return p.name || p.sid;
}

// Group one user's TD events into plays: a passing TD pairs with a receiving TD
// by a player on the SAME NFL team in the same poll (that's one play). Events for
// players not in the user's snapshot are dropped.
function groupPlays(events, roster) {
  const mine = events.filter((e) => roster[e.sid]);
  const passes = mine.filter((e) => e.cat === 'p');
  const used = new Set();
  const plays = [];
  for (const e of mine) {
    if (e.cat === 'p') continue;
    const members = [e];
    if (e.cat === 'c') {
      const team = roster[e.sid].team;
      const q = passes.find((x) => !used.has(x) && team && roster[x.sid].team === team);
      if (q) { used.add(q); members.push(q); }
    }
    plays.push(members);
  }
  for (const q of passes) if (!used.has(q)) plays.push([q]);
  return plays;
}

// Build the alert for one play for one user, or null when it shouldn't alert
// (no player in the play is on the user's side anywhere = Enemy-only).
function buildPlayAlert(members, roster, seasonWeek) {
  const helps = new Set(), hurts = new Set();
  for (const m of members) {
    const p = roster[m.sid];
    (p.mine || []).forEach((l) => helps.add(l));
    (p.opp || []).forEach((l) => hurts.add(l));
  }
  const both = [...helps].filter((l) => hurts.has(l));
  both.forEach((l) => { helps.delete(l); hurts.delete(l); });
  if (!helps.size && !both.length) return null;

  const rec = members.find((m) => m.cat === 'c');
  const qb = members.find((m) => m.cat === 'p');
  const delta = Math.max(...members.map((m) => m.to - m.from));
  let title;
  if (rec && qb) title = `${displayName(roster[qb.sid])} to ${displayName(roster[rec.sid])}, TD.`;
  else {
    const m = members[0];
    const who = displayName(roster[m.sid]);
    if (delta > 1) title = `${who}, ${delta} TDs.`;
    else if (m.cat === 'p') title = `${who} TD pass.`;
    else title = `${who} TD.`;
  }
  const parts = [];
  if (helps.size) parts.push(`Helps you in ${listJoin([...helps])}.`);
  if (hurts.size) parts.push(`Hurts you in ${listJoin([...hurts])}.`);
  if (both.length) parts.push(`Both ways in ${listJoin(both)}.`);

  const ordered = members.slice().sort((a, b) => CAT_ORDER.indexOf(a.cat) - CAT_ORDER.indexOf(b.cat));
  const key = [seasonWeek, ...ordered.map(memberKey)].join('|');
  return {
    key,
    message: {
      kind: 'td',
      title,
      body: parts.join(' '),
      url: '/?push=td',
      tag: tagFromKey(key)
    }
  };
}

// "sid:cat:count", plus ".rev" once a TD at that count has been called back — so a
// player who scores again after a reversal gets a fresh alert, not a dedupe hit.
function memberKey(e) { return `${e.sid}:${e.cat}:${e.to}` + (e.rev ? `.${e.rev}` : ''); }

function tagFromKey(key) {
  const first = String(key).split('|')[1] || 'x';
  return 'td-' + first.replace(/[^A-Za-z0-9:._-]/g, '');
}

// "Called back" alert for a TD we already sent (same tag, so it replaces it).
function buildCalledBack(sentKey, sid, roster) {
  return {
    kind: 'td',
    title: `${displayName(roster[sid])} TD called back.`,
    body: 'Taken off the board.',
    url: '/?push=td',
    tag: tagFromKey(sentKey)
  };
}

module.exports = {
  tdCounts, countsFromStats, diffCounts, groupPlays, buildPlayAlert, buildCalledBack,
  tagFromKey, memberKey, listJoin, displayName, isDefSid
};
