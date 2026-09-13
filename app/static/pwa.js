(() => {
  'use strict';
  const RELEASE = '0.55.2';
  let deferredInstallPrompt = null;

  const standalone = () => window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;
  const csrfToken = () => document.querySelector('meta[name="zen-csrf"]')?.content || document.querySelector('input[name="csrf"]')?.value || '';

  function setInstallState(state, detail = '') {
    document.querySelectorAll('[data-pwa-state]').forEach(el => {
      el.textContent = state;
      el.dataset.state = state.toLowerCase().replace(/\s+/g, '-');
    });
    document.querySelectorAll('[data-pwa-detail]').forEach(el => { el.textContent = detail; });
    document.querySelectorAll('[data-pwa-install]').forEach(button => {
      button.hidden = standalone() || !deferredInstallPrompt;
      button.disabled = !deferredInstallPrompt;
    });
  }

  function setPushState(state, detail = '', options = {}) {
    document.querySelectorAll('[data-push-state]').forEach(el => {
      el.textContent = state;
      el.dataset.state = state.toLowerCase().replace(/\s+/g, '-');
    });
    document.querySelectorAll('[data-push-detail]').forEach(el => { el.textContent = detail; });
    document.querySelectorAll('[data-push-enable]').forEach(button => {
      button.hidden = Boolean(options.subscribed);
      button.disabled = !options.canEnable;
    });
    document.querySelectorAll('[data-push-disable]').forEach(button => {
      button.hidden = !options.subscribed;
      button.disabled = !options.subscribed;
    });
    document.querySelectorAll('[data-push-test]').forEach(button => {
      button.disabled = !options.subscribed;
    });
  }

  function createUpdateBanner(registration) {
    if (document.querySelector('[data-pwa-update-banner]')) return;
    const banner = document.createElement('div');
    banner.className = 'pwa-update-banner';
    banner.dataset.pwaUpdateBanner = '1';
    banner.setAttribute('role', 'status');
    banner.innerHTML = '<div><strong>ZEN Control update ready</strong><span>Reload to use the latest application shell.</span></div><button type="button" class="primary">Reload</button>';
    banner.querySelector('button').addEventListener('click', () => {
      registration.waiting?.postMessage({type: 'SKIP_WAITING'});
    });
    document.body.appendChild(banner);
  }

  async function registerServiceWorker() {
    if (!window.isSecureContext) {
      setInstallState('HTTPS REQUIRED', 'Android/Chromium installation requires HTTPS (localhost is the development exception).');
      return null;
    }
    if (!('serviceWorker' in navigator)) {
      setInstallState('UNSUPPORTED', 'This browser does not provide service-worker support.');
      return null;
    }
    try {
      const registration = await navigator.serviceWorker.register('/service-worker.js', {scope: '/'});
      if (registration.waiting) createUpdateBanner(registration);
      registration.addEventListener('updatefound', () => {
        const worker = registration.installing;
        worker?.addEventListener('statechange', () => {
          if (worker.state === 'installed' && navigator.serviceWorker.controller) createUpdateBanner(registration);
        });
      });
      navigator.serviceWorker.addEventListener('controllerchange', () => window.location.reload());
      setInstallState(standalone() ? 'INSTALLED' : 'READY', standalone() ? `Standalone app · v${RELEASE}` : `Installable web app · v${RELEASE}`);
      return registration;
    } catch (_error) {
      setInstallState('UNAVAILABLE', 'Service worker registration failed; normal browser access still works.');
      return null;
    }
  }

  function urlBase64ToUint8Array(value) {
    const padding = '='.repeat((4 - value.length % 4) % 4);
    const base64 = (value + padding).replace(/-/g, '+').replace(/_/g, '/');
    const raw = window.atob(base64);
    return Uint8Array.from([...raw].map(character => character.charCodeAt(0)));
  }

  async function jsonRequest(url, options = {}) {
    const response = await fetch(url, {
      cache: 'no-store',
      credentials: 'same-origin',
      ...options,
      headers: {
        'Content-Type': 'application/json',
        'X-ZEN-CSRF': csrfToken(),
        ...(options.headers || {})
      }
    });
    let body = {};
    try { body = await response.json(); } catch (_error) { body = {}; }
    if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
    return body;
  }

  async function pushContext() {
    if (!window.isSecureContext) throw new Error('HTTPS is required for browser push.');
    if (!('serviceWorker' in navigator) || !('PushManager' in window) || !('Notification' in window)) {
      throw new Error('This browser does not support Web Push.');
    }
    const registration = await navigator.serviceWorker.ready;
    const config = await jsonRequest('/api/notifications/push', {method: 'GET', headers: {'Content-Type': 'application/json'}});
    const subscription = await registration.pushManager.getSubscription();
    return {registration, config, subscription};
  }

  async function refreshPushState() {
    if (!document.querySelector('[data-push-state]')) return;
    if (!window.isSecureContext) {
      setPushState('HTTPS REQUIRED', 'Push needs the HTTPS ZEN URL; HTTP cannot register a browser push subscription.', {canEnable: false, subscribed: false});
      return;
    }
    if (!('serviceWorker' in navigator) || !('PushManager' in window) || !('Notification' in window)) {
      setPushState('UNSUPPORTED', 'This browser does not expose the standard Web Push APIs.', {canEnable: false, subscribed: false});
      return;
    }
    try {
      const {config, subscription} = await pushContext();
      if (Notification.permission === 'denied') {
        setPushState('BLOCKED', 'Browser notification permission is blocked. Allow notifications in this site\'s browser settings.', {canEnable: false, subscribed: Boolean(subscription)});
        return;
      }
      if (subscription) {
        setPushState('SUBSCRIBED', `Browser push active · ${config.subscriptions.enabled || 0} enabled server subscription(s)`, {canEnable: false, subscribed: true});
      } else {
        setPushState('AVAILABLE', 'Enable push on this browser/PWA to receive ZEN attention events.', {canEnable: true, subscribed: false});
      }
    } catch (error) {
      setPushState('UNAVAILABLE', error.message || 'Push status could not be loaded.', {canEnable: false, subscribed: false});
    }
  }

  async function enablePush(button) {
    button.disabled = true;
    try {
      const permission = await Notification.requestPermission();
      if (permission !== 'granted') throw new Error('Notification permission was not granted.');
      const {registration, config, subscription: existing} = await pushContext();
      const subscription = existing || await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(config.public_key)
      });
      await jsonRequest('/api/notifications/push/subscriptions', {
        method: 'POST',
        body: JSON.stringify({subscription: subscription.toJSON()})
      });
      setPushState('SUBSCRIBED', 'Browser push is enabled on this device.', {canEnable: false, subscribed: true});
      await refreshPushState();
    } catch (error) {
      setPushState('ERROR', error.message || 'Push subscription failed.', {canEnable: true, subscribed: false});
    } finally {
      button.disabled = false;
    }
  }

  async function disablePush(button) {
    button.disabled = true;
    try {
      const registration = await navigator.serviceWorker.ready;
      const subscription = await registration.pushManager.getSubscription();
      if (subscription) {
        await jsonRequest('/api/notifications/push/unsubscribe', {
          method: 'POST',
          body: JSON.stringify({endpoint: subscription.endpoint})
        });
        await subscription.unsubscribe();
      }
      setPushState('AVAILABLE', 'Browser push is disabled on this device.', {canEnable: true, subscribed: false});
      await refreshPushState();
    } catch (error) {
      setPushState('ERROR', error.message || 'Push unsubscribe failed.', {canEnable: false, subscribed: true});
    } finally {
      button.disabled = false;
    }
  }

  async function testPush(button) {
    button.disabled = true;
    const original = button.textContent;
    try {
      const result = await jsonRequest('/api/notifications/push/test', {method: 'POST', body: '{}'});
      button.textContent = `Queued ${result.queued}`;
      setTimeout(() => { button.textContent = original; refreshPushState(); }, 2500);
    } catch (error) {
      button.textContent = 'Test failed';
      setPushState('ERROR', error.message || 'Test push failed.', {canEnable: false, subscribed: true});
      setTimeout(() => { button.textContent = original; }, 2500);
    } finally {
      button.disabled = false;
    }
  }

  window.addEventListener('beforeinstallprompt', event => {
    event.preventDefault();
    deferredInstallPrompt = event;
    setInstallState('READY TO INSTALL', `Android/browser install available · v${RELEASE}`);
  });

  window.addEventListener('appinstalled', () => {
    deferredInstallPrompt = null;
    setInstallState('INSTALLED', `Standalone app · v${RELEASE}`);
  });

  document.addEventListener('click', async event => {
    const installButton = event.target.closest('[data-pwa-install]');
    if (installButton && deferredInstallPrompt) {
      installButton.disabled = true;
      deferredInstallPrompt.prompt();
      await deferredInstallPrompt.userChoice;
      deferredInstallPrompt = null;
      setInstallState(standalone() ? 'INSTALLED' : 'READY', `Install prompt completed · v${RELEASE}`);
      return;
    }
    const pushEnable = event.target.closest('[data-push-enable]');
    if (pushEnable) { await enablePush(pushEnable); return; }
    const pushDisable = event.target.closest('[data-push-disable]');
    if (pushDisable) { await disablePush(pushDisable); return; }
    const pushTest = event.target.closest('[data-push-test]');
    if (pushTest) { await testPush(pushTest); }
  });

  document.addEventListener('DOMContentLoaded', async () => {
    setInstallState(standalone() ? 'INSTALLED' : 'CHECKING', `ZEN Control PWA · v${RELEASE}`);
    await registerServiceWorker();
    await refreshPushState();
  });
})();
