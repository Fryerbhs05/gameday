// api/_lib/status-alerts.js
// Builds the Sunday-night status and Tuesday results alerts for one account:
// NFL week + game states (Sleeper state, ESPN scoreboard) → live matchups from
// the account's own connections (league-reader) → Snapshot-logic copy (status-core).

const R = require('./league-reader');
const C = require('./status-core');

const SLEEPER = 'https://api.sleeper.app/v1';
const SCOREBOARD = 'https://site.api.espn.com/apis/site/v2/sports/football/nfl/scoreboard';

async function getJson(url) {
  const sep = url.includes('?') ? '&' : '?';
  const r = await fetch(`${url}${sep}_cb=${Date.now()}`, { headers: { Accept: 'application/json' } });
  if (!r.ok) throw new Error(`${new URL(url).hostname} ${r.status}`);
  return r.json();
}

async function nflState() {
  const s = await getJson(`${SLEEPER}/state/nfl`);
  return { season: String(s.season || ''), week: +s.week || 0, type: String(s.season_type || '') };
}

function etWeekday(ms) {
  return new Intl.DateTimeFormat('en-US', { timeZone: 'America/New_York', weekday: 'short' }).format(new Date(ms));
}

// { states: Map(team -> 'pre'|'in'|'post'), loaded, events: [{ms, state, sunday, monday, teams}] }
async function weekGames(season, week, type) {
  const st = type === 'post' ? 3 : 2;
  try {
    const j = await getJson(`${SCOREBOARD}?dates=${season}&seasontype=${st}&week=${week}`);
    const states = new Map(), events = [];
    for (const e of j.events || []) {
      const comp = e.competitions && e.competitions[0];
      const state = comp && comp.status && comp.status.type && comp.status.type.state;
      const ms = Date.parse(e.date);
      const wd = etWeekday(ms), teams = [];
      for (const c of (comp && comp.competitors) || []) {
        const ab = c.team && c.team.abbreviation;
        if (ab) { states.set(C.normTeam(ab), state); teams.push(C.normTeam(ab)); }
      }
      events.push({ ms, state, sunday: wd === 'Sun', monday: wd === 'Mon', teams });
    }
    return { states, loaded: events.length > 0, events };
  } catch (e) {
    console.error('weekGames failed', e.message);
    return { states: new Map(), loaded: false, events: [] };
  }
}

// The most recent week whose games are ALL final (Tuesday's target).
async function completedWeek(ns) {
  const g = await weekGames(ns.season, ns.week, ns.type);
  const allPost = g.events.length > 0 && g.events.every((e) => e.state === 'post');
  return allPost ? ns.week : Math.max(1, ns.week - 1);
}

// Monday games this week: { kickoff: first Monday kickoff ms, teams: Set }.
function mondaySlate(games) {
  const mon = (games.events || []).filter((e) => e.monday && Number.isFinite(e.ms));
  if (!mon.length) return null;
  const teams = new Set();
  mon.forEach((e) => (e.teams || []).forEach((t) => teams.add(t)));
  return { kickoff: Math.min(...mon.map((e) => e.ms)), teams, events: mon };
}

// mode: 'snf' | 'tue' | 'mnf'. Returns { message, rows, week } or null when there's nothing to say.
// mnf + ctx.preview (Settings test button): Monday games are treated as not yet
// kicked off, so the test shows the pre-kickoff heads-up any day of the week.
async function buildForUser(uid, mode, ctx) {
  const ns = (ctx && ctx.ns) || await nflState();
  if (mode === 'mnf') {
    const week = ns.week;
    let games = (ctx && ctx.games) || await weekGames(ns.season, week, ns.type);
    const slate = mondaySlate(games);
    if (!slate) return null;
    if (ctx && ctx.preview) {
      const states = new Map(games.states);
      slate.teams.forEach((t) => states.set(t, 'pre'));
      games = { ...games, states };
    }
    const matchups = await R.readAccountMatchups(uid, ns.season, week);
    const msg = C.mnfMessage(matchups, games, slate.teams);
    if (!msg) return null;
    return { week, rows: msg.names, message: { kind: 'mnf', title: msg.title, body: msg.body, url: '/?push=mnf', tag: `cf-mnf-${ns.season}-${week}` } };
  }
  if (mode === 'tue') {
    const week = (ctx && ctx.week) || await completedWeek(ns);
    const matchups = await R.readAccountMatchups(uid, ns.season, week);
    const msg = C.tuesdayMessage(matchups, week);
    if (!msg) return null;
    return { week, rows: msg.rows, message: { kind: 'tue', title: msg.title, body: msg.body, url: '/?push=tue', tag: `cf-tue-${ns.season}-${week}` } };
  }
  const week = ns.week;
  const games = (ctx && ctx.games) || await weekGames(ns.season, week, ns.type);
  const matchups = await R.readAccountMatchups(uid, ns.season, week);
  const msg = C.snfMessage(matchups, games);
  if (!msg) return null;
  return { week, rows: msg.rows, message: { kind: 'snf', title: msg.title, body: msg.body, url: '/?push=snf', tag: `cf-snf-${ns.season}-${week}` } };
}

module.exports = { nflState, weekGames, completedWeek, buildForUser, etWeekday, mondaySlate };
