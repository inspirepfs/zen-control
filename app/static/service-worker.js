/* ZEN Control v0.38 PWA service worker.
 * Security boundary: only presentation assets and the sanitized offline page
 * are cached. Authenticated HTML/API responses and all mutations remain
 * network-only and are never queued for replay.
 */
const RELEASE = '0.54.5.1';
const CACHE_NAME = `zen-control-shell-${RELEASE}`;
const OFFLINE_URL = '/static/offline.html';
const SHELL_ASSETS = [
  OFFLINE_URL,
  `/static/pwa.css?v=${RELEASE}`,
  `/static/pwa.js?v=${RELEASE}`,
  `/static/help.css?v=${RELEASE}`,
  `/pwa/icon/180.png?v=${RELEASE}`,
  `/pwa/icon/192.png?v=${RELEASE}`,
  `/pwa/icon/512.png?v=${RELEASE}`,
  `/static/manifest.webmanifest?v=${RELEASE}`
];

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(SHELL_ASSETS)));
});

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    const names = await caches.keys();
    await Promise.all(names.filter(name => name.startsWith('zen-control-shell-') && name !== CACHE_NAME).map(name => caches.delete(name)));
    await self.clients.claim();
  })());
});

self.addEventListener('message', event => {
  if (event.data?.type === 'SKIP_WAITING') self.skipWaiting();
  if (event.data?.type === 'ZEN_PWA_STATUS' && event.ports?.[0]) {
    event.ports[0].postMessage({release: RELEASE, cache: CACHE_NAME, offlineMutations: false, cachedPrivateData: false});
  }
});

self.addEventListener('fetch', event => {
  const request = event.request;
  if (request.method !== 'GET') return; // Mutations are always direct network requests.

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  if (request.mode === 'navigate') {
    event.respondWith((async () => {
      try {
        return await fetch(request, {cache: 'no-store'});
      } catch (_error) {
        return (await caches.match(OFFLINE_URL)) || Response.error();
      }
    })());
    return;
  }

  // Dynamic application/API responses are never cached by the service worker.
  const safePresentationAsset = url.pathname.startsWith('/static/') || url.pathname.startsWith('/pwa/icon/');
  if (!safePresentationAsset) {
    event.respondWith(fetch(request, {cache: 'no-store'}));
    return;
  }

  // Static presentation assets and embedded install icons are safe for cache-first delivery. Versioned
  // URLs plus cache replacement on activation provide deterministic updates.
  event.respondWith((async () => {
    const cached = await caches.match(request);
    if (cached) return cached;
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, response.clone());
    }
    return response;
  })());
});
