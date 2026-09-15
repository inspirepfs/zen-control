(() => {
  'use strict';
  const RELEASE = '0.59.0';
  let deferredInstallPrompt = null;
  let currentRegistration = null;
  const browserDiagnostics = {
    schema: 'zen_pwa_browser_diagnostics_v1',
    version: RELEASE,
    secureContext: Boolean(window.isSecureContext),
    standalone: false,
    displayMode: 'browser',
    installEventApiDetected: ('onbeforeinstallprompt' in window) || ('BeforeInstallPromptEvent' in window),
    beforeInstallPromptReceived: false,
    appInstalledEventReceived: false,
    lastPromptOutcome: 'not_run',
    serviceWorker: {
      supported: 'serviceWorker' in navigator,
      registered: false,
      active: false,
      waiting: false,
      installing: false,
      controller: false,
      scopePath: null,
    },
    manifest: {
      linkPresent: false,
      loaded: false,
      id: null,
      scope: null,
      startUrl: null,
      display: null,
      iconSizes: [],
      error: null,
    },
    notifications: {
      supported: 'Notification' in window,
      permission: 'Notification' in window ? Notification.permission : 'unsupported',
    },
    push: {
      supported: ('PushManager' in window) && ('serviceWorker' in navigator),
      subscribed: null,
    },
  };

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


  function currentDisplayMode() {
    for (const mode of ['fullscreen', 'standalone', 'minimal-ui', 'window-controls-overlay', 'browser']) {
      try {
        if (window.matchMedia(`(display-mode: ${mode})`).matches) return mode;
      } catch (_error) { /* Browser does not understand this display mode. */ }
    }
    return standalone() ? 'standalone' : 'browser';
  }

  function installDiagnosis() {
    if (standalone()) {
      return {state: 'INSTALLED', detail: `Running in standalone app mode · v${RELEASE}`};
    }
    if (!window.isSecureContext) {
      return {state: 'HTTPS REQUIRED', detail: 'A secure HTTPS context is required for normal PWA installation and service-worker use.'};
    }
    if (!browserDiagnostics.serviceWorker.supported) {
      return {state: 'UNSUPPORTED', detail: 'This browser does not expose service-worker support.'};
    }
    if (!browserDiagnostics.manifest.linkPresent) {
      return {state: 'MANIFEST MISSING', detail: 'The page has no web-app manifest link.'};
    }
    if (browserDiagnostics.manifest.error) {
      return {state: 'MANIFEST UNAVAILABLE', detail: 'The web-app manifest could not be loaded or parsed.'};
    }
    if (!browserDiagnostics.serviceWorker.registered) {
      return {state: 'SERVICE WORKER UNAVAILABLE', detail: 'A root-scope service worker is not registered on this page.'};
    }
    if (deferredInstallPrompt) {
      return {state: 'READY TO INSTALL', detail: `The browser offered an install prompt on this page · v${RELEASE}`};
    }
    if (browserDiagnostics.lastPromptOutcome === 'dismissed') {
      return {state: 'PROMPT DISMISSED', detail: 'The last browser install prompt was dismissed. A new prompt requires the browser to offer another install event.'};
    }
    if (browserDiagnostics.lastPromptOutcome === 'accepted') {
      return {state: 'INSTALL ACCEPTED', detail: 'The browser accepted the install request; waiting for installed/standalone evidence.'};
    }
    if (!browserDiagnostics.installEventApiDetected) {
      return {state: 'BROWSER-MANAGED', detail: 'This browser does not expose the Chromium beforeinstallprompt API. Use its own install/Add to Home Screen UI if available.'};
    }
    return {
      state: 'PROMPT NOT OFFERED',
      detail: 'PWA prerequisites are loaded, but this browser has not offered beforeinstallprompt on this page. This can mean already installed, browser/device policy, an in-app/custom tab, unmet browser criteria, or browser-managed install UI.',
    };
  }

  function diagnosticRows() {
    const diagnosis = installDiagnosis();
    return [
      ['Install decision', diagnosis.state, diagnosis.detail],
      ['Secure context', browserDiagnostics.secureContext ? 'YES' : 'NO', 'HTTPS/browser secure-context evidence'],
      ['Display mode', browserDiagnostics.displayMode.toUpperCase(), browserDiagnostics.standalone ? 'Standalone evidence detected' : 'Normal browser/tab mode'],
      ['Manifest', browserDiagnostics.manifest.loaded ? 'LOADED' : (browserDiagnostics.manifest.error ? 'ERROR' : 'CHECKING'), browserDiagnostics.manifest.loaded ? `${browserDiagnostics.manifest.display || 'display unknown'} · icons ${browserDiagnostics.manifest.iconSizes.join(', ') || 'not declared'}` : 'Browser manifest prerequisite'],
      ['Service worker', browserDiagnostics.serviceWorker.registered ? 'REGISTERED' : (browserDiagnostics.serviceWorker.supported ? 'NOT REGISTERED' : 'UNSUPPORTED'), `active ${browserDiagnostics.serviceWorker.active ? 'yes' : 'no'} · controller ${browserDiagnostics.serviceWorker.controller ? 'yes' : 'no'}`],
      ['Install event API', browserDiagnostics.installEventApiDetected ? 'DETECTED' : 'NOT DETECTED', `beforeinstallprompt received ${browserDiagnostics.beforeInstallPromptReceived ? 'yes' : 'no'}`],
      ['Install event', browserDiagnostics.appInstalledEventReceived ? 'APPINSTALLED SEEN' : 'NOT SEEN', `last prompt outcome ${browserDiagnostics.lastPromptOutcome}`],
      ['Notifications', browserDiagnostics.notifications.supported ? browserDiagnostics.notifications.permission.toUpperCase() : 'UNSUPPORTED', 'Browser notification permission only; no endpoint or keys are displayed'],
      ['Push subscription', browserDiagnostics.push.supported ? (browserDiagnostics.push.subscribed === true ? 'SUBSCRIBED' : (browserDiagnostics.push.subscribed === false ? 'NOT SUBSCRIBED' : 'UNKNOWN')) : 'UNSUPPORTED', 'Device-local subscription presence only'],
    ];
  }

  function renderPwaDiagnostics() {
    browserDiagnostics.secureContext = Boolean(window.isSecureContext);
    browserDiagnostics.standalone = standalone();
    browserDiagnostics.displayMode = currentDisplayMode();
    if ('Notification' in window) browserDiagnostics.notifications.permission = Notification.permission;
    const rows = diagnosticRows();
    document.querySelectorAll('[data-pwa-diagnostics]').forEach(container => {
      container.replaceChildren();
      rows.forEach(([label, state, detail]) => {
        const row = document.createElement('div');
        row.className = 'pwa-diagnostic-row';
        const heading = document.createElement('div');
        heading.className = 'pwa-diagnostic-heading';
        const name = document.createElement('strong');
        name.textContent = label;
        const badge = document.createElement('span');
        badge.className = 'pwa-state';
        badge.textContent = state;
        heading.append(name, badge);
        const copy = document.createElement('span');
        copy.className = 'muted small';
        copy.textContent = detail;
        row.append(heading, copy);
        container.appendChild(row);
      });
    });
  }

  async function inspectManifest() {
    const link = document.querySelector('link[rel~="manifest"]');
    browserDiagnostics.manifest.linkPresent = Boolean(link?.href);
    browserDiagnostics.manifest.loaded = false;
    browserDiagnostics.manifest.error = null;
    if (!link?.href) return;
    try {
      const response = await fetch(link.href, {cache: 'no-store', credentials: 'same-origin'});
      if (!response.ok) throw new Error('manifest_http_error');
      const manifest = await response.json();
      browserDiagnostics.manifest.loaded = true;
      browserDiagnostics.manifest.id = typeof manifest.id === 'string' ? manifest.id : null;
      browserDiagnostics.manifest.scope = typeof manifest.scope === 'string' ? manifest.scope : null;
      browserDiagnostics.manifest.startUrl = typeof manifest.start_url === 'string' ? manifest.start_url : null;
      browserDiagnostics.manifest.display = typeof manifest.display === 'string' ? manifest.display : null;
      browserDiagnostics.manifest.iconSizes = Array.isArray(manifest.icons)
        ? [...new Set(manifest.icons.map(icon => String(icon?.sizes || '')).filter(Boolean))].sort()
        : [];
    } catch (_error) {
      browserDiagnostics.manifest.error = 'load_or_parse_failed';
    }
  }

  async function inspectServiceWorker(registration = null) {
    if (!browserDiagnostics.serviceWorker.supported) return null;
    try {
      const current = registration || currentRegistration || await navigator.serviceWorker.getRegistration('/');
      if (current) currentRegistration = current;
      browserDiagnostics.serviceWorker.registered = Boolean(current);
      browserDiagnostics.serviceWorker.active = Boolean(current?.active);
      browserDiagnostics.serviceWorker.waiting = Boolean(current?.waiting);
      browserDiagnostics.serviceWorker.installing = Boolean(current?.installing);
      browserDiagnostics.serviceWorker.controller = Boolean(navigator.serviceWorker.controller);
      if (current?.scope) {
        try { browserDiagnostics.serviceWorker.scopePath = new URL(current.scope).pathname; }
        catch (_error) { browserDiagnostics.serviceWorker.scopePath = '/'; }
      }
      if (current?.pushManager) {
        try { browserDiagnostics.push.subscribed = Boolean(await current.pushManager.getSubscription()); }
        catch (_error) { browserDiagnostics.push.subscribed = null; }
      }
      return current;
    } catch (_error) {
      browserDiagnostics.serviceWorker.registered = false;
      browserDiagnostics.serviceWorker.active = false;
      browserDiagnostics.serviceWorker.controller = Boolean(navigator.serviceWorker.controller);
      return null;
    }
  }

  async function refreshPwaDiagnostics(registration = null) {
    await Promise.all([inspectManifest(), inspectServiceWorker(registration)]);
    const diagnosis = installDiagnosis();
    setInstallState(diagnosis.state, diagnosis.detail);
    renderPwaDiagnostics();
  }

  function diagnosticSnapshot() {
    const diagnosis = installDiagnosis();
    return {
      schema: browserDiagnostics.schema,
      version: browserDiagnostics.version,
      install: {
        state: diagnosis.state,
        secure_context: browserDiagnostics.secureContext,
        display_mode: browserDiagnostics.displayMode,
        standalone: browserDiagnostics.standalone,
        install_event_api_detected: browserDiagnostics.installEventApiDetected,
        beforeinstallprompt_received: browserDiagnostics.beforeInstallPromptReceived,
        appinstalled_received: browserDiagnostics.appInstalledEventReceived,
        last_prompt_outcome: browserDiagnostics.lastPromptOutcome,
      },
      manifest: {...browserDiagnostics.manifest},
      service_worker: {...browserDiagnostics.serviceWorker},
      notifications: {...browserDiagnostics.notifications},
      push: {...browserDiagnostics.push},
      privacy: 'device-local capability state only; no hostname, credentials, subscription endpoint, household policy or activity data',
    };
  }

  async function copyDiagnostics(button) {
    const text = JSON.stringify(diagnosticSnapshot(), null, 2);
    let copied = false;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
        copied = true;
      }
    } catch (_error) { copied = false; }
    if (!copied) {
      const area = document.createElement('textarea');
      area.value = text;
      area.setAttribute('readonly', '');
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.appendChild(area);
      area.select();
      try { copied = document.execCommand('copy'); } catch (_error) { copied = false; }
      area.remove();
    }
    const status = document.querySelector('[data-pwa-diagnostics-copy-status]');
    if (status) status.textContent = copied ? 'Diagnostic summary copied.' : 'Copy was blocked by the browser; use DevTools window.ZEN_PWA_DIAGNOSTICS().';
    if (button) button.textContent = copied ? 'Copied' : 'Copy unavailable';
    setTimeout(() => { if (button) button.textContent = 'Copy diagnostics'; }, 1800);
  }

  window.ZEN_PWA_DIAGNOSTICS = () => diagnosticSnapshot();

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
      currentRegistration = registration;
      await inspectServiceWorker(registration);
      const diagnosis = installDiagnosis();
      setInstallState(diagnosis.state, diagnosis.detail);
      return registration;
    } catch (_error) {
      browserDiagnostics.serviceWorker.registered = false;
      setInstallState('UNAVAILABLE', 'Service worker registration failed; normal browser access still works.');
      renderPwaDiagnostics();
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
    browserDiagnostics.beforeInstallPromptReceived = true;
    browserDiagnostics.lastPromptOutcome = 'not_run';
    setInstallState('READY TO INSTALL', `The browser offered an install prompt on this page · v${RELEASE}`);
    renderPwaDiagnostics();
  });

  window.addEventListener('appinstalled', () => {
    deferredInstallPrompt = null;
    browserDiagnostics.appInstalledEventReceived = true;
    browserDiagnostics.lastPromptOutcome = 'accepted';
    setInstallState('INSTALLED', `Standalone app installed · v${RELEASE}`);
    renderPwaDiagnostics();
  });

  document.addEventListener('click', async event => {
    const installButton = event.target.closest('[data-pwa-install]');
    if (installButton && deferredInstallPrompt) {
      installButton.disabled = true;
      const prompt = deferredInstallPrompt;
      try {
        await prompt.prompt();
        const choice = await prompt.userChoice;
        browserDiagnostics.lastPromptOutcome = choice?.outcome || 'unknown';
      } catch (_error) {
        browserDiagnostics.lastPromptOutcome = 'error';
      }
      deferredInstallPrompt = null;
      const diagnosis = installDiagnosis();
      setInstallState(diagnosis.state, diagnosis.detail);
      await refreshPwaDiagnostics(currentRegistration);
      return;
    }
    const diagnosticsRefresh = event.target.closest('[data-pwa-diagnostics-refresh]');
    if (diagnosticsRefresh) {
      diagnosticsRefresh.disabled = true;
      try { await refreshPwaDiagnostics(currentRegistration); }
      finally { diagnosticsRefresh.disabled = false; }
      return;
    }
    const diagnosticsCopy = event.target.closest('[data-pwa-diagnostics-copy]');
    if (diagnosticsCopy) { await copyDiagnostics(diagnosticsCopy); return; }
    const pushEnable = event.target.closest('[data-push-enable]');
    if (pushEnable) { await enablePush(pushEnable); return; }
    const pushDisable = event.target.closest('[data-push-disable]');
    if (pushDisable) { await disablePush(pushDisable); return; }
    const pushTest = event.target.closest('[data-push-test]');
    if (pushTest) { await testPush(pushTest); }
  });

  document.addEventListener('DOMContentLoaded', async () => {
    setInstallState(standalone() ? 'INSTALLED' : 'CHECKING', `ZEN Control PWA · v${RELEASE}`);
    renderPwaDiagnostics();
    const registration = await registerServiceWorker();
    await refreshPwaDiagnostics(registration);
    await refreshPushState();
    setTimeout(() => { refreshPwaDiagnostics(currentRegistration); }, 1500);
  });

  window.addEventListener('pageshow', () => { refreshPwaDiagnostics(currentRegistration); });
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) refreshPwaDiagnostics(currentRegistration);
  });
})();
