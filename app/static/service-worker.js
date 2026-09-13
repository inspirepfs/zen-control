/* ZEN Control PWA service worker.
 * Security boundary: only presentation assets and the sanitized offline page
 * are cached. Authenticated HTML/API responses and all mutations remain
 * network-only and are never queued for replay. Web Push payloads are shown
 * transiently by the browser and are not persisted by this service worker.
 */
const RELEASE = '0.57.0';
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
    event.ports[0].postMessage({release: RELEASE, cache: CACHE_NAME, offlineMutations: false, cachedPrivateData: false, pushNotifications: true});
  }
});

self.addEventListener('push', event => {
  event.waitUntil((async () => {
    let data = {};
    try { data = event.data ? event.data.json() : {}; } catch (_error) {
      data = {title: 'ZEN Control', body: event.data ? event.data.text() : 'New notification'};
    }
    const severity = String(data.severity || 'info').toLowerCase();
    const target = String(data.url || '/?view=notifications&section=inbox#notifications/inbox');
    const options = {
      body: String(data.body || ''),
      icon: `/pwa/icon/192.png?v=${RELEASE}`,
      badge: `/pwa/icon/192.png?v=${RELEASE}`,
      tag: String(data.tag || `zen-notification-${data.notification_id || Date.now()}`),
      renotify: severity === 'critical',
      requireInteraction: severity === 'critical',
      timestamp: Date.parse(data.timestamp || '') || Date.now(),
      data: {url: target, notificationId: data.notification_id || 0, severity}
    };
    await self.registration.showNotification(String(data.title || 'ZEN Control'), options);
  })());
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil((async () => {
    let target;
    try {
      target = new URL(String(event.notification.data?.url || '/?view=notifications&section=inbox#notifications/inbox'), self.location.origin);
      if (target.origin !== self.location.origin) target = new URL('/?view=notifications&section=inbox#notifications/inbox', self.location.origin);
    } catch (_error) {
      target = new URL('/?view=notifications&section=inbox#notifications/inbox', self.location.origin);
    }
    const windows = await self.clients.matchAll({type: 'window', includeUncontrolled: true});
    for (const client of windows) {
      if ('focus' in client) {
        await client.navigate(target.href);
        return client.focus();
      }
    }
    return self.clients.openWindow(target.href);
  })());
});

self.addEventListener('fetch', event => {
  const request = event.request;
  if (request.method !== 'GET') return;
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

  const safePresentationAsset = url.pathname.startsWith('/static/') || url.pathname.startsWith('/pwa/icon/');
  if (!safePresentationAsset) {
    event.respondWith(fetch(request, {cache: 'no-store'}));
    return;
  }

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
