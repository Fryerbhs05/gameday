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

const CACHE_VERSION = 'conflicted-v94'; // v94: Matchup drawer — team abbreviations removed + "Player 12345" eliminated (Matt, 2026-07-20). (1) Dropped the NFL team abbreviation line under each player name in the paired rows (the matchup-drawer__player-team span in halfCells); the centered POS chips are untouched. (2) Fixed raw "Player <id>" labels appearing when a Sleeper matchup was opened during a cold open. Root cause: Sleeper stores raw player IDs and the drawer resolves names from window.playerDB at OPEN time, but on a snapshot boot the board is clickable before that ~5MB DB loads (Yahoo/ESPN embed the name, so were never affected; the canonical Sleeper-ID mapping is a separate build-time layer and isn't involved). Three-part fix: (a) the boot IIFE now hydrates window.playerDB synchronously from its localStorage cache BEFORE the snapshot paints/becomes clickable, deliberately IGNORING the 12h CACHE_TTL — the TTL governs when to refetch, but a stale DB renders names fine, and honoring it skipped the hydrate for anyone opening a day later (most cold opens); loadData still refetches and overwrites. (b) new rerenderOpenMatchupDrawer() repaints an open drawer in place once loadData sets window.playerDB, self-healing without a close+reopen. (c) normalizePlayer now splits the two ways an ID lookup comes back empty and never renders the raw ID for either: DB-not-loaded-yet = TRANSIENT → new `pending` flag renders the app's standard .skel shimmer bar in the name slot (84px / 68px mobile, reduced-motion inherited); DB-loaded-but-ID-missing = PERMANENT (new signing / stale cache) → neutral "Unknown player", since a shimmer there would spin forever. v93: Removed the doubled header above the league toggles (Matt, 2026-07-19). The shared cfRenderLeagueSection() partial already renders its own 'League / Show' column head, but both host sheets were wrapping it in another heading — Leaders in <h4>LEAGUES</h4> and Exposure in a 'Leagues' settings label — so the control read as two stacked headers saying nearly the same word. Dropped both wrappers and kept the shared column head, since that one also labels the Show column.
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
