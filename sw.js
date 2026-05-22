/* ============================================================
   Conflicted — service worker
   v1: app-shell caching + branded offline fallback.
   Strategy: network-first for everything (so users always get
   fresh scores when online), with /offline.html as the fallback
   for failed navigation requests.
   ============================================================ */

const CACHE_VERSION = 'conflicted-v2';
const OFFLINE_URL = '/offline.html';

/* Files cached at install so the offline page always works,
   even before the user has ever loaded the site online. */
const PRECACHE_ASSETS = [
  '/offline.html',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/brand-kit/logo/conflicted-wordmark-color.svg',
  '/brand-kit/logo/conflicted-favicon.svg'
];

/* ---- Install: pre-cache the offline page + brand assets ---- */
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_VERSION).then((cache) => cache.addAll(PRECACHE_ASSETS))
      .then(() => self.skipWaiting())
  );
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

/* ---- Fetch: network-first, fall back to offline page ---- */
self.addEventListener('fetch', (event) => {
  const req = event.request;

  // Only handle GET; let everything else (POST to /api/*) pass through.
  if (req.method !== 'GET') return;

  // For navigation requests (loading a page), try network, fall back to offline.
  // Important: a 401/403 is NOT an offline condition — the user is online but
  // their session expired. Pass those through so the app can render its own
  // "session expired / reconnect" state instead of the offline fallback.
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req).then((res) => res).catch(() => caches.match(OFFLINE_URL))
    );
    return;
  }

  // For other GETs (icons, fonts), try network, fall back to cache.
  event.respondWith(
    fetch(req).catch(() => caches.match(req))
  );
});
