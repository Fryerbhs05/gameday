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

const CACHE_VERSION = 'conflicted-v53'; // v53: Landing phone stage v2 — replaced the simplified minis with a faithful static port of Claude Design's Phone Loyalties/Phone Scoreboard mockups (native 402×874 iOS shell w/ island+status+home bar, scaled .63 desktop / .42 mobile, .lps-* classes, inline bisected wordmark since brand-kit/ never deploys); landing footer gains About link → showAbout(). Also added "Claude Design Training/" to .vercelignore so design docs never deploy. v52: Landing page 1B redesign (Claude Design) — hero copy "Your best player just scored. For both teams." + CTA pair (Get started scroll / demo), static tilted phone-pair stage split by the brand seam (decorative Loyalties + Scoreboard minis, .lpp-*), How-it-works converted to ledger rows on a recessed paper-deep band, demo panel moved out of the signin card into a dashed "Not ready to connect?" panel (keeps #demo-tryfirst for setDemoVisible), landing footer (© + Privacy); wizard incl. "Don't see your platform?" untouched. v51: Scoreboard + Loyalties redesign (Claude Design 2a/3a/4a) — score cells and player cards move to shared navy tiles (--tile-bg/--tile-line, radius-lg); score rows collapse to one line (your score status-colored left, opp muted right); live cells declare WINNING/TOSS-UP/LOSING · LIVE from projections (±3 pt toss-up band, matching top accent); finals show FINAL SCORE with a full result-colored bar + "✓ Won · +X.X" margin; coral-tick section titles (SCOREBOARD/LOYALTIES/LIVE UPDATES), header week context retired; share export gains "Winning N of X" hero + final/live sub-line. v50: Conflict Card pre-lock states — replaced the always-"Sharpening for tonight/SUNDAY" placeholder with a 3-state machine: Offseason (message + static SAMPLE demo card), Gate 1 games-underway (feature explainer + dimmed shape-only preview, adaptive night kicker), Gate 2 pre-kickoff (names the conflicted SNF/MNF players + preview); come-back copy adapts to SNF/MNF; missing slot map on an in-season week now fires cfTrack('conflict_card_error'). v49: ESPN cookie-expiry reconnect banner — fires when ESPN was connected but the session expired; mobile users told to reconnect on desktop + offered an emailed desktop link. v48: simplified share footer — dropped the QR entirely; footer is now just wordmark (left) + ConflictedApp.com (right) on one row across scoreboard/snapshot/conflict-card. v47: retired the split-C favicon entirely (removed from index/offline/s.html + precache, files deleted); no favicon anywhere. Share preview now fully imageless. v46: compact /s.html?ref= share link for small iMessage preview
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
