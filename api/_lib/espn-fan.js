// api/_lib/espn-fan.js
// League auto-discovery via ESPN's "fan" API. Given a user's espn_s2 + SWID,
// returns every fantasy-FOOTBALL league tied to that SWID — the same data ESPN's
// own app uses to populate your league list. This is what lets us default-add
// all of a user's leagues (like Sleeper/Yahoo) instead of asking for a league ID.
//
// This file lives under api/_lib/ so Vercel does NOT treat it as a serverless
// function (underscore-prefixed dirs are ignored for routing) — it's required()
// by save.js and data.js, same pattern as accounts.js.
//
// NOTE: the fan API response shape is only lightly documented. The parser below
// is deliberately defensive (checks several known field locations, then falls
// back to a bounded deep-scan for groupId) and never throws — worst case it
// returns an empty list and the caller falls back to a manual league ID.

const FAN_HOST = 'https://fan.api.espn.com';

// ESPN sport abbreviations seen on fan entries. We want football (FFL) only.
// FBA=basketball, FLB=baseball, FHL=hockey, FFL=football.
const FOOTBALL_ABBREVS = new Set(['FFL']);

function uaHeaders(s2, swid) {
  return {
    Cookie: `espn_s2=${s2}; SWID=${swid}`,
    'User-Agent':
      'Mozilla/5.0 (compatible; ConflictedFantasy/1.0; +https://conflicted-fantasy.vercel.app)',
    Accept: 'application/json'
  };
}

// Pull {leagueId, name, seasonId} rows out of one fan "preference" entry.
function leaguesFromEntry(entry, sink) {
  if (!entry || typeof entry !== 'object') return;
  const abbrev = String(entry.abbrev || entry.gameAbbrev || '').toUpperCase();
  // If an abbrev is present and it isn't football, skip. If absent, keep it —
  // a non-football id queried against the FFL endpoint just 404s downstream.
  if (abbrev && !FOOTBALL_ABBREVS.has(abbrev)) return;

  const seasonId = entry.seasonId || entry.season || null;
  const groups = Array.isArray(entry.groups) ? entry.groups : [];
  groups.forEach((g) => {
    const id = g && (g.groupId != null ? g.groupId : g.id);
    if (id == null) return;
    sink.push({
      leagueId: String(id),
      name: String(g.groupName || g.name || entry.name || `ESPN League ${id}`),
      seasonId: seasonId != null ? Number(seasonId) : null
    });
  });
}

// Bounded deep-scan fallback: walk the object looking for any { groupId, groupName }
// shaped nodes. Capped in depth/breadth so a huge payload can't run away.
function deepScanForGroups(node, sink, depth) {
  if (depth > 6 || node == null || typeof node !== 'object') return;
  if (node.groupId != null) {
    sink.push({
      leagueId: String(node.groupId),
      name: String(node.groupName || node.name || `ESPN League ${node.groupId}`),
      seasonId: node.seasonId != null ? Number(node.seasonId) : null
    });
  }
  const keys = Object.keys(node);
  for (let i = 0; i < keys.length && i < 200; i++) {
    const v = node[keys[i]];
    if (v && typeof v === 'object') deepScanForGroups(v, sink, depth + 1);
  }
}

function parseFanResponse(data) {
  const rows = [];
  if (data && Array.isArray(data.preferences)) {
    data.preferences.forEach((pref) => {
      const entry = pref && pref.metaData && pref.metaData.entry;
      if (entry) leaguesFromEntry(entry, rows);
      // Some payloads attach the entry directly on the preference.
      if (pref && pref.entry) leaguesFromEntry(pref.entry, rows);
    });
  }
  // Fallback if the primary path found nothing.
  if (!rows.length && data && typeof data === 'object') {
    deepScanForGroups(data, rows, 0);
  }

  // Dedupe by leagueId, keeping the row with the most recent season (so the
  // display name reflects the latest renewal). League IDs persist across
  // seasons, so one id covers all of a league's history.
  const byId = new Map();
  rows.forEach((r) => {
    if (!r.leagueId) return;
    const prev = byId.get(r.leagueId);
    if (!prev || (r.seasonId || 0) > (prev.seasonId || 0)) byId.set(r.leagueId, r);
  });
  return Array.from(byId.values());
}

// Main entry. Returns { leagues: [{leagueId,name,seasonId}], error: string|null }.
// Never throws.
async function discoverLeagues(espnS2, swid) {
  if (!espnS2 || !swid) return { leagues: [], error: 'missing credentials' };
  const url =
    `${FAN_HOST}/apis/v2/fans/${encodeURIComponent(swid)}` +
    `?displayHidden=true&context=fantasy&useCookieAuth=true&featureFlags=fanApiFavorites`;
  try {
    const res = await fetch(url, { headers: uaHeaders(espnS2, swid) });
    if (!res.ok) {
      return { leagues: [], error: `fan API HTTP ${res.status}` };
    }
    const data = await res.json();
    return { leagues: parseFanResponse(data), error: null };
  } catch (e) {
    return { leagues: [], error: e.message || 'fan API fetch failed' };
  }
}

module.exports = { discoverLeagues, parseFanResponse };
