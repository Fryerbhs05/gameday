// api/espn/data.js
// Authenticated proxy to the ESPN Fantasy API. Reads the encrypted session
// cookie set by /api/espn/save.js, attaches the user's espn_s2 + SWID to
// the outbound request, and returns ESPN's JSON response.
//
// Usage from the frontend:
//   /api/espn/data?endpoint=league&season=2025                 — league metadata + settings + teams
//   /api/espn/data?endpoint=teams&season=2025                  — teams + records (mTeam view)
//   /api/espn/data?endpoint=roster&season=2025&week=10         — all rosters for the week (mRoster)
//   /api/espn/data?endpoint=matchups&season=2025&week=10       — head-to-head scoreboard for the week
//   /api/espn/data?endpoint=boxscore&season=2025&week=10       — full boxscores w/ per-player points
//   /api/espn/data?endpoint=history                            — list seasons this league has data for
//
// The session stores the user's full set of league ids (session.lids; legacy
// single session.lid still honoured). Pass ?league_id=<id> to pick which one to
// read — it must be one of the stored ids. With no league_id we default to the
// first. endpoint=discover re-runs fan-API discovery and self-heals the set.

const crypto = require('crypto');

// Optional accounts layer — inert unless Supabase env vars are configured.
let A = null;
try { A = require('../_lib/accounts'); } catch (e) { A = null; }

// League auto-discovery (fan API). Used by the endpoint=discover action.
let FAN = null;
try { FAN = require('../_lib/espn-fan'); } catch (e) { FAN = null; }

const ALGO_ENC = 'aes-256-gcm';
function encryptBlob(plain, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO_ENC, key, iv);
  const enc = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString('base64url');
}

const ALGO = 'aes-256-gcm';

function getKey() {
  const secret = process.env.SESSION_SECRET;
  if (!secret) throw new Error('SESSION_SECRET not set');
  return crypto.createHash('sha256').update(secret).digest();
}

function decrypt(sealed) {
  const buf = Buffer.from(sealed, 'base64url');
  const iv = buf.slice(0, 12);
  const tag = buf.slice(12, 28);
  const data = buf.slice(28);
  const decipher = crypto.createDecipheriv(ALGO, getKey(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach((c) => {
    const i = c.indexOf('=');
    if (i > -1) {
      out[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim());
    }
  });
  return out;
}

// ESPN host pattern:
//   Current/recent seasons:  https://lm-api-reads.fantasy.espn.com/apis/v3/games/ffl/seasons/{year}/segments/0/leagues/{leagueId}
//   Pre-2018 historical:     https://lm-api-reads.fantasy.espn.com/apis/v3/games/ffl/leagueHistory/{leagueId}?seasonId={year}
// We default to the seasons URL — if a user ever needs deep history pre-2018, add a flag.
function buildEspnUrl(leagueId, season, views, week) {
  const base = `https://lm-api-reads.fantasy.espn.com/apis/v3/games/ffl/seasons/${encodeURIComponent(
    season
  )}/segments/0/leagues/${encodeURIComponent(leagueId)}`;
  const params = new URLSearchParams();
  views.forEach((v) => params.append('view', v));
  if (week != null) params.set('scoringPeriodId', String(week));
  return `${base}?${params.toString()}`;
}

module.exports = async (req, res) => {
  try {
    const cookies = parseCookies(req);

    // Prefer the per-browser cookie (today's path). If it's absent — e.g. the
    // user is on their phone where they never pasted cookies — fall back to the
    // ESPN blob stored against their signed-in account. This is the payoff of
    // the accounts layer: connect once on desktop, works everywhere after.
    let sealed = cookies.espn_session || null;
    if (!sealed) {
      try {
        if (A && A.accountsConfigured()) {
          const acct = A.readAccount(req);
          if (acct) sealed = await A.getPlatformSession(acct.uid, 'espn');
        }
      } catch (e) {
        console.error('espn/data account lookup failed (non-fatal):', e.message);
      }
    }

    if (!sealed) {
      res.status(401).json({
        error: 'Not authenticated. POST credentials to /api/espn/save first.'
      });
      return;
    }

    let session;
    try {
      session = JSON.parse(decrypt(sealed));
    } catch (e) {
      res.status(401).json({ error: 'Invalid ESPN session' });
      return;
    }

    const espnS2 = session.s2;
    const swid = session.sw;

    // Full league set (array). Fall back to the legacy single id for sessions
    // saved before multi-league. The requested league_id must belong to the set.
    const lids = Array.isArray(session.lids) && session.lids.length
      ? session.lids.map(String)
      : (session.lid ? [String(session.lid)] : []);

    const endpoint = (req.query.endpoint || 'league').toString();

    // ── discover: re-run fan-API discovery, refresh the stored set, return it ──
    // Lets the client repopulate leagues without a re-paste, and self-heals a
    // session whose discovery failed at save time. Re-seals the cookie (and the
    // account blob) so the new set sticks.
    if (endpoint === 'discover') {
      if (!FAN) { res.status(200).json({ leagues: [], error: 'discovery unavailable' }); return; }
      const d = await FAN.discoverLeagues(espnS2, swid);
      const leagues = Array.isArray(d.leagues) ? d.leagues : [];
      if (leagues.length) {
        const newLids = [];
        const lnames = {};
        leagues.forEach((l) => {
          const sid = String(l.leagueId);
          if (/^[0-9]+$/.test(sid) && !newLids.includes(sid)) { newLids.push(sid); lnames[sid] = l.name; }
        });
        // Preserve any legacy/manual ids already in the session that the fan API
        // didn't return (e.g. a league the user added by hand).
        lids.forEach((id) => { if (!newLids.includes(id)) newLids.push(id); });
        const refreshed = JSON.stringify({ ...session, lid: newLids[0], lids: newLids, lnames: { ...(session.lnames || {}), ...lnames } });
        try {
          const sealedNew = encryptBlob(refreshed, getKey());
          res.setHeader('Set-Cookie', `espn_session=${sealedNew}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`);
          if (A && A.accountsConfigured()) {
            const acct = A.readAccount(req);
            if (acct) await A.savePlatformSession(acct.uid, 'espn', sealedNew);
          }
        } catch (e) { console.error('discover re-seal failed (non-fatal):', e.message); }
      }
      res.status(200).json({ leagues, error: d.error || null });
      return;
    }

    // Resolve which league this request reads. Default to the first stored id.
    const requestedLid = req.query.league_id
      ? String(req.query.league_id).replace(/[^0-9]/g, '')
      : null;
    if (requestedLid && !lids.includes(requestedLid)) {
      res.status(403).json({ error: 'Requested league is not part of your connected ESPN set.' });
      return;
    }
    const leagueId = requestedLid || lids[0];
    if (!leagueId) {
      res.status(409).json({ error: 'No ESPN league on file. Re-connect ESPN.' });
      return;
    }
    const season = req.query.season
      ? String(req.query.season).replace(/[^0-9]/g, '')
      : new Date().getFullYear().toString();
    const week = req.query.week
      ? Number(String(req.query.week).replace(/[^0-9]/g, ''))
      : null;

    // Map our friendly endpoint names to ESPN's `view` parameters.
    // ESPN supports stacking multiple views in one call (efficient — fewer
    // requests, ESPN's rate limiting is per-request not per-view).
    let views;
    if (endpoint === 'league') {
      views = ['mSettings', 'mTeam', 'mNav'];
    } else if (endpoint === 'teams') {
      views = ['mTeam'];
    } else if (endpoint === 'roster') {
      if (week == null) {
        res.status(400).json({ error: 'week is required for roster endpoint' });
        return;
      }
      views = ['mRoster'];
    } else if (endpoint === 'matchups') {
      views = ['mMatchup', 'mMatchupScore'];
    } else if (endpoint === 'boxscore') {
      if (week == null) {
        res.status(400).json({ error: 'week is required for boxscore endpoint' });
        return;
      }
      // mBoxscore gives full per-player point breakdowns for each matchup.
      // We bundle mTeam so the client gets team names in the same payload.
      views = ['mBoxscore', 'mMatchupScore', 'mTeam', 'mRoster'];
    } else if (endpoint === 'history') {
      // Lightweight call to validate auth + show what season we're on.
      views = ['mNav'];
    } else {
      res.status(400).json({ error: `Unknown endpoint: ${endpoint}` });
      return;
    }

    const url = buildEspnUrl(leagueId, season, views, week);

    const espnRes = await fetch(url, {
      headers: {
        // ESPN's lm-api-reads host accepts cookies in two forms; the Cookie
        // header is the safest. SWID + espn_s2 together identify the user.
        Cookie: `espn_s2=${espnS2}; SWID=${swid}`,
        // ESPN occasionally rejects requests with no UA; pretend to be a browser.
        'User-Agent':
          'Mozilla/5.0 (compatible; ConflictedFantasy/1.0; +https://conflicted-fantasy.vercel.app)',
        Accept: 'application/json'
      }
    });

    if (espnRes.status === 401) {
      // Most common cause: espn_s2 rotated or user logged out of ESPN.
      // Clear the session so the frontend re-prompts for new cookies.
      res.setHeader(
        'Set-Cookie',
        `espn_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
      );
      res.status(401).json({
        error: 'ESPN session expired or invalid — please re-connect ESPN.'
      });
      return;
    }

    if (espnRes.status === 404) {
      res.status(404).json({
        error: 'League not found for this season. Check your league ID and that the league existed in this year.',
        league_id: leagueId,
        season
      });
      return;
    }

    if (!espnRes.ok) {
      const txt = await espnRes.text();
      res.status(espnRes.status).json({
        error: 'ESPN API error',
        status: espnRes.status,
        detail: txt.slice(0, 500)
      });
      return;
    }

    const data = await espnRes.json();
    res.status(200).json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};
