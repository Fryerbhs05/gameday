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

// { states: Map(team -> 'pre'|'in'|'post'), loaded, events: [{ms, state, sunday}] }
async function weekGames(season, week, type) {
  const st = type === 'post' ? 3 : 2;
  try {
    const j = await getJson(`${SCOREBOARD}?dates=${season}&seasontype=${st}&week=${week}`);
    const states = new Map(), events = [];
    for (const e of j.events || []) {
      const comp = e.competitions && e.competitions[0];
      const state = comp && comp.status && comp.status.type && comp.status.type.state;
      const ms = Date.parse(e.date);
      events.push({ ms, state, sunday: etWeekday(ms) === 'Sun' });
      for (const c of (comp && comp.competitors) || []) {
        const ab = c.team && c.team.abbreviation;
        if (ab) states.set(C.normTeam(ab), state);
      }
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

// mode: 'snf' | 'tue'. Returns { message, rows, week } or null when there's nothing to say.
async function buildForUser(uid, mode, ctx) {
  const ns = (ctx && ctx.ns) || await nflState();
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

module.exports = { nflState, weekGames, completedWeek, buildForUser, etWeekday };
