/* ============================================================
   Conflicted — service worker
   v2: cache-first APP SHELL + branded offline fallback.

   Why cache-first for the shell: on a resumed/backgrounded PWA,
   iOS reloads the whole page. Network-first made that reload wait
   on the network to re-download index.html before anything painted
   — the multi-second "login screen, then flash, then loading"
   resume jank. We now serve the cached shell INSTANTLY and refresh
   it in the background (stale-while-revalidate), so the app paints
   immediately on resume. Live scores are unaffected: they come from
   /api/* (POST, passed straight through) and data GETs, never the
   HTML document.
   ============================================================ */

const CACHE_VERSION = 'conflicted-v114'; // v114: Standardized desktop phone-preview scroll cap (Matt, 2026-07-23). Introduced a shared :root token --cf-phone-scroll-max (440px): the scrollable list region of any phone-framed desktop board caps at this height and scrolls internally so the phone stays a natural height instead of stretching the page. Applied to BOTH the Snapshot content (.cf-snap-content-d) and Leaders rows (.ldr-frame-d .ldr-rows) — replaced Leaders' earlier fixed-height(620)+flex approach (which shrank+clipped rows) with the cleaner max-height-on-scroll-region pattern; wordmark/hero/total stay pinned above, Snapshot foot stays below. .ldr-rows is a column flexbox so its children get flex:0 0 auto to keep natural height (each .ldr-row is overflow:hidden and would otherwise clip). Short Snapshot lists render naturally shorter; the cap only bites when content would stretch the phone. Future phone-framed views (Conflict Card next) should reuse --cf-phone-scroll-max. v113: Desktop Leaders = 3-column feature layout, mirroring the Snapshot treatment (Matt, 2026-07-23). At ≥900px the Leaders view drops the mobile single card/Carried-Crushed toggle/share button and shows an informative framed COPY column ("Who carried you. Who crushed you.") beside two phone-framed boards — Carried Me (center) and Crushed Me (right) — painted by render()/paintLdrDesktop()/ldrFrameInner() from the same rows as mobile (parametrized by side F/A instead of st.side), always showing ALL rows. Column captions colored green (Carried) / red (Crushed). Nudge = "Built for mobile · Email me the link" → ldrEmailLink() POSTs the signed-in account email to /api/auth/magic/request; demo hides button+divider+hint. Each board in a .ldr-phone-frame edge frame, notch-clearing top padding, responsive (≥1200 three cols / 900–1199 copy on top + 2 boards / <900 mobile). The shared period bar is centered+constrained to 600px and its Carried/Crushed toggle row hidden on desktop Leaders (override extended to .pb-leaders, placed after the shared rules for source order). NEW: Leaders added to the hamburger menu (Views section, shows in demo) — it was previously unreachable on desktop since the bottom nav is mobile-only (≤768px) and Leaders wasn't in the hamburger. Mobile Leaders untouched. v112: Desktop Weekend Snapshot = 3-column feature layout (Matt, 2026-07-23). At ≥900px the Snapshot view drops the mobile single card/toggle/share button and shows an informative framed COPY column beside two phone-framed List + Grid previews, painted by the same render()/buildRows/cardHTML/tileHTML so the preview can't drift from the real cards. Copy is informative (framed around checking/managing leagues), with a "Built for mobile · Email me the link" nudge that POSTs the signed-in account email to /api/auth/magic/request (one-click login link); demo mode hides the email button+divider+hint (no account). Each phone wrapped in .cf-phone-frame (navy-line edge frame matching the copy frame), notch-clearing top padding so the wordmark clears the decorative notch. Responsive: ≥1200 three columns / 900–1199 copy stacks on top + 2 phones side by side / <900 mobile view. The shared period bar is centered + constrained to 600px on desktop Snapshot and its List/Grid toggle row hidden — the override is placed AFTER the shared .pb-snapshot rules (~L16959) so it wins source order (an earlier-in-file rule silently loses). Weekend Snapshot menu item de-gated from menu-signedin-only so it shows in the desktop demo hamburger. Mobile Snapshot untouched. v111: Account > League Connections — Yahoo connect no longer full-page-redirects (Matt, 2026-07-22). Clicking "Connect to Yahoo" from the Account view used to run window.location.href='/api/auth/yahoo', which navigated the whole SPA away; after OAuth the callback cold-boots the app at '/', and during a Yahoo hiccup (e.g. the read-permission outage) that reboot dumped the signed-in user on the logged-out landing page. Now the Account view reuses the wizard's new-tab OAuth (?wizard=1 self-closing callback) and polls /api/yahoo/data from the page (connectionsConnectYahoo/pollConnectionsYahoo) so the user never leaves Account: 200=connected, 401=still finishing OAuth (keep polling ~75s), 403=Yahoo declined (outage) → inline plain-language detail message on the Yahoo card. Poll stopped + state cleared on view enter/exit. Pre-login setup grid keeps the old full-page redirect (landing is fine there). v110: Removed the TEMP Yahoo API outage banner (Matt, 2026-07-22). Yahoo restored our Fantasy Sports read permission app-side — runtime logs confirm /api/yahoo/data returning 200s with real league data as of ~20:20 UTC, no more 403 "This application is not authorized". Deleted the whole self-contained banner block (style#cf-yahoo-outage-style + div#cf-yahoo-outage + IIFE) that sat right after <body> in index.html; <body> now flows straight into the Boot splash again. Version bumped so the in-app Refresh prompt fires and users stop seeing the banner same-session. v109: TEMP Yahoo API outage banner (Matt, 2026-07-22). Yahoo dropped our Fantasy Sports read permission app-side, so all Yahoo league data is coming back empty. Added a self-contained, dismissible fixed top banner (first block after <body> in index.html, --surf-* chrome palette + amber pulse dot) that shows on every screen incl. the Yahoo connect flow, regardless of whether the user has a Yahoo league. Dismissal is session-only (sessionStorage cfYahooOutageDismissed_v1) so it returns next visit while the outage persists. body.cf-outage-on reserves --cf-outage-h (JS-measured) padding-top and parks the sticky header just below the banner. REMOVE the whole TEMP block + this note once the Yahoo app permission is restored. v108: Hero CTA buttons no longer stretch full-width on mobile (Matt, 2026-07-22). flex:1 1 0 was making each button fill half the row (too wide); switched the ≤640px primary row to flex:0 0 auto with a shared min-width:136px — sized to the wider "Get started" label + padding — so both stay equal and the centered pair sits at natural width instead of edge-to-edge. Still nowrap/side-by-side. v107: Hero CTA pair stays side-by-side on mobile (Matt, 2026-07-22). At ≤640px the two 210px-min buttons were wrapping to two rows; added a mobile rule so the primary row (.lp-cta-row:not(--secondary)) is flex-wrap:nowrap with the buttons flex:1 1 0 / min-width:0 — they now drop the fixed width and share the row, shrinking to fit any phone width. Desktop symmetry (210px min-width) unchanged; demo/ghost row unaffected. v106: Sign-in modal decluttered (Matt, 2026-07-22). Removed the "or / Get started / Sign up" section from openSignInModal() — the modal is now sign-in only (email + magic-link button). Dropped the espn-modal-or divider, the Get started heading, the #signin-signup button, and its orphaned click handler (which would have thrown on the now-missing element). New users still reach the funnel via the hero "Get started" button; no need to repeat it here. v105: Hero pair made symmetrical + sign-in spam note (Matt, 2026-07-22). (1) Sign in / Get started now render equal width — min-width:210px + centered text on .lp-cta-row:not(--secondary) .btn-hero — so the two-button row is symmetrical regardless of label length; demo/ghost row exempt. (2) Added a brand-tone spam-folder line to the "Check your email" confirmation in openSignInModal(): "No link within 10 seconds? Check your spam folder — it likes to hide there sometimes." v104: Landing hero CTA split into a two-button row for returning users (Matt, 2026-07-22). Added a "Sign in" button to the LEFT of "Get started", colored to match the split wordmark — .btn-hero--signin uses var(--navy-700) (#7AA8D1, the blue left half) with the same dark #0F1B26 label and 15px/28px padding as the coral --primary (var(--coral-500), the right half); hover lightens navy via color-mix. Sign in wires to openSignInModal() (magic-link path for existing users), Get started keeps scrollToGetStarted(). This surfaces sign-in that was previously buried behind the hamburger → "Sign in" item. The "Try demo mode" ghost button moved to a second .lp-cta-row--secondary row below the pair (12px gap), so the primary row is the clean Sign in / Get started pair. v103: Blue frame added around the app icon in the PWA install drawer — 1.5px --navy-500 border on .cf-install__icon, box-sizing:border-box so the tile stays 52px (Matt, 2026-07-22). v102: Snapshot share bar widened to match Leaders (Matt, 2026-07-22). The mobile bottom share bar was a different width on Snapshot (420px cap) vs Leaders (520px cap). Since Leaders' bar lines up perfectly with its card frame, brought Snapshot to match: .cf-snap-wrap max-width 420→520 and the fixed .cf-snap-share width min() cap 420→520, so the Snapshot card + share bar now equal Leaders' 520px and the bar stays flush with the framing on both views. v101: Scoreboard/Rooting Card share icon brightened to full --ink-900 (was --ink-500) with a heavier stroke (2.75), matching the section wordmark weight (Matt, 2026-07-22). v100: PWA install prompt moved from floating banner to the shared BottomSheet drawer (Matt, 2026-07-22). Same 30s post-dashboard dwell trigger and all gating (in-app/demo/standalone checks, beforeinstallprompt capture) unchanged, but presentation now reuses window.BottomSheet (owner 'pwa-install') so it matches the app's other drawers — grab handle, .55 backdrop, scroll-lock. Content: home-screen icon (icon-192), reordered benefits (Full screen, no browser bar / One tap from your home screen / No password to remember), Android real one-tap Install (deferredPrompt.prompt via .btn-primary) with "Not now", iOS shows browser-aware Share → Add to Home Screen steps with "Got it". Naggy by design: dismissal only suppresses for the current session (sessionDismissed flag), no 30-day localStorage persistence — re-summons every visit. Old #conflicted-install-banner element, its <style>, and the tab-bar offset rule removed. v99: Priority onboarding deferred to returning users (Matt, 2026-07-22). The "rank your leagues" screen no longer auto-launches on a user's first visit — they now get to land on the dashboard, see their connected leagues, and look around first. shouldAutoLaunchPriority now records the first dashboard visit (localStorage gd_priority_first_seen) and tags the session that created it (sessionStorage gd_priority_first_session); the prompt only fires once they return in a LATER session with priorities still unset. First-visit renders/refreshes within that first session no longer trigger it. Demo mode, the <2-league guard, isPrioritySet(), and the Settings "Re-rank" path are all unchanged. v98: Rooting-direction dots extended to ALL loyalty cards (Matt, 2026-07-20). Cheer/Enemy card league-row dots now use the same semantic colors as Conflicted cards — green (--cheer) = your roster, red (--enemy) = opponent's — replacing league-color dots everywhere in the buckets; the 0.5 dim on opponent rows is gone since red carries the signal. v97: Loyalties buckets made strictly disjoint (Matt, 2026-07-20). User feedback: conflicted players appearing under Cheer, Enemy, AND Conflicted tabs was confusing. Removed the mobile-only concat that surfaced conflicted players (gold-framed) inside the Cheer/Enemy lists — they now live ONLY in the Conflicted tab, on every viewport. To preserve the rooting guidance those duplicate placements gave, conflicted cards' league-row dots are now rooting-direction dots: green (--cheer) where the player is on YOUR roster in that league, red (--enemy) where your opponent has him — replacing the league-color dots on conflicted cards only. Enemy-side rows on conflicted cards drop the 0.5 dim so the red reads full-strength. Cheer/Enemy cards keep league-color dots, unchanged. v96: ESPN renewal-status probe, diagnostic only (Matt, 2026-07-20). ESPN has no clean renewal signal (Sleeper/Yahoo pending-league discovery can't cover it), so before designing detection we capture what ESPN's payload actually says: new lean `probe` endpoint on api/espn/data.js (views mSettings+mStatus+mDraftDetail+mNav — no rosters/boxscore), client fires it once per league+season per session on live-period loads (this season AND the prior one for a renewed-vs-carryover comparison), 4s off the render path, deduped, fire-and-forget. Fields (status.isActive/previousSeasons/teamsJoined/dates, draftDetail.drafted/picks, draftSettings date/type/keeperCount, schedule shape, seasonId echo, non-200 statuses) go out via cfTrack('espn_renewal_probe') — readback SQL in db/espn-renewal-probe.sql — and mirror to window.__espnProbe. Zero behavior change; remove the block once detection ships.  League show/hide races + Rooting Card leak (Matt, 2026-07-20). (1) Rooting Card now applies the shared hiddenLeagues filter: players from Filters-hidden leagues are dropped from the card, and every count (hero numbers, ×N flanks, sort weights, the 'N leagues' sub-line) is computed from VISIBLE leagues only — players are cloned so __conflictedLastData stays pristine for the dashboard. (2) Race A self-heal: loadData stamps each request with a signature (season|week|providers#disabled) and its coalescing guard now settles through __settleSelfHeal — if the user changed period or toggled a league while a fetch flew (toggle-off → week change → toggle-on), one fresh load is chained and the stale result is discarded, never rendered. (3) Race B cache poisoning: the historic-cache key is captured at request time (__reqKey) alongside a snapshot of the disabled set (__reqDisabled, used for the post-fetch filter), so a mid-flight toggle can no longer file differently-filtered data under the wrong key. v94: Matchup drawer — team abbreviations removed + "Player 12345" eliminated (Matt, 2026-07-20). (1) Dropped the NFL team abbreviation line under each player name in the paired rows (the matchup-drawer__player-team span in halfCells); the centered POS chips are untouched. (2) Fixed raw "Player <id>" labels appearing when a Sleeper matchup was opened during a cold open. Root cause: Sleeper stores raw player IDs and the drawer resolves names from window.playerDB at OPEN time, but on a snapshot boot the board is clickable before that ~5MB DB loads (Yahoo/ESPN embed the name, so were never affected; the canonical Sleeper-ID mapping is a separate build-time layer and isn't involved). Three-part fix: (a) the boot IIFE now hydrates window.playerDB synchronously from its localStorage cache BEFORE the snapshot paints/becomes clickable, deliberately IGNORING the 12h CACHE_TTL — the TTL governs when to refetch, but a stale DB renders names fine, and honoring it skipped the hydrate for anyone opening a day later (most cold opens); loadData still refetches and overwrites. (b) new rerenderOpenMatchupDrawer() repaints an open drawer in place once loadData sets window.playerDB, self-healing without a close+reopen. (c) normalizePlayer now splits the two ways an ID lookup comes back empty and never renders the raw ID for either: DB-not-loaded-yet = TRANSIENT → new `pending` flag renders the app's standard .skel shimmer bar in the name slot (84px / 68px mobile, reduced-motion inherited); DB-loaded-but-ID-missing = PERMANENT (new signing / stale cache) → neutral "Unknown player", since a shimmer there would spin forever. v93: Removed the doubled header above the league toggles (Matt, 2026-07-19). The shared cfRenderLeagueSection() partial already renders its own 'League / Show' column head, but both host sheets were wrapping it in another heading — Leaders in <h4>LEAGUES</h4> and Exposure in a 'Leagues' settings label — so the control read as two stacked headers saying nearly the same word. Dropped both wrappers and kept the shared column head, since that one also labels the Show column.
const OFFLINE_URL = '/offline.html';
const APP_SHELL_URL = '/'; // canonical cache key for the single-page shell

/* Files cached at install so the shell + offline page work instantly,
   even before the user has ever loaded the site online. */
const PRECACHE_ASSETS = [
  '/',
  '/index.html',
  '/offline.html',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/brand-kit/logo/conflicted-wordmark-color.svg'
];

/* ---- Install: pre-cache the shell + offline page + brand assets ----
   NOTE: we deliberately do NOT call skipWaiting() here. On an UPDATE (an old
   SW is still controlling open tabs) the new SW installs and then WAITS, so the
   page can show a "new version available — tap to refresh" prompt and activate
   it on the user's command (see the SKIP_WAITING message handler below). On a
   first-ever install there's no controller to replace, so it activates normally
   and clients.claim() (in activate) takes control of the open page. */
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_VERSION)
      // Individual puts so one missing asset can't fail the whole install.
      .then((cache) => Promise.all(
        PRECACHE_ASSETS.map((url) =>
          cache.add(url).catch((e) => console.warn('precache skip', url, e && e.message))
        )
      ))
  );
});

/* ---- Activate the waiting worker on demand (user tapped "Refresh") ---- */
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') self.skipWaiting();
});

/* ---- Activate: clean up old caches from prior versions ---- */
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.filter((k) => k !== CACHE_VERSION).map((k) => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

/* Revalidate the shell in the background: fetch a fresh copy and store it
   so the NEXT load gets the update. Failures are swallowed (offline etc.). */
function revalidateShell(req) {
  return fetch(req).then((res) => {
    if (res && res.ok) {
      const copy = res.clone();
      caches.open(CACHE_VERSION).then((cache) => cache.put(APP_SHELL_URL, copy)).catch(() => {});
    }
    return res;
  }).catch(() => null);
}

/* ---- Fetch ---- */
self.addEventListener('fetch', (event) => {
  const req = event.request;

  // Only handle GET; let everything else (POST to /api/*) pass through.
  if (req.method !== 'GET') return;

  if (req.mode === 'navigate') {
    const path = new URL(req.url).pathname;
    // Only the single-page app shell is served cache-first. Standalone pages
    // (e.g. /privacy.html) must NOT be replaced by the app shell — they stay
    // network-first with cache fallback.
    const isAppShell = (path === '/' || path === '/index.html');

    if (isAppShell) {
      // CACHE-FIRST shell + background revalidate. Paints instantly on resume.
      // If the shell isn't cached yet (first ever visit), fall back to network,
      // then the offline page. Note: a 401/403 is NOT an offline condition — the
      // user is online but their session expired; the app renders its own
      // reconnect state from the cached shell.
      event.respondWith(
        caches.match(APP_SHELL_URL).then((cached) => {
          if (cached) {
            revalidateShell(req); // refresh cache for next time, don't block paint
            return cached;
          }
          return fetch(req)
            .then((res) => {
              if (res && res.ok) {
                const copy = res.clone();
                caches.open(CACHE_VERSION).then((cache) => cache.put(APP_SHELL_URL, copy)).catch(() => {});
              }
              return res;
            })
            .catch(() => caches.match(OFFLINE_URL));
        })
      );
      return;
    }

    // Other pages: network-first, fall back to cache, then offline page.
    event.respondWith(
      fetch(req).catch(() => caches.match(req).then((c) => c || caches.match(OFFLINE_URL)))
    );
    return;
  }

  // Other GETs (icons, fonts, brand assets): cache-first, fall back to network.
  event.respondWith(
    caches.match(req).then((cached) => cached || fetch(req))
  );
});
