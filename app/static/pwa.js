(() => {
  'use strict';
  const RELEASE = '0.54.4';
  let deferredInstallPrompt = null;

  const standalone = () => window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;

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
      return;
    }
    if (!('serviceWorker' in navigator)) {
      setInstallState('UNSUPPORTED', 'This browser does not provide service-worker support.');
      return;
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
    } catch (_error) {
      setInstallState('UNAVAILABLE', 'Service worker registration failed; normal browser access still works.');
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
    const button = event.target.closest('[data-pwa-install]');
    if (!button || !deferredInstallPrompt) return;
    button.disabled = true;
    deferredInstallPrompt.prompt();
    await deferredInstallPrompt.userChoice;
    deferredInstallPrompt = null;
    setInstallState(standalone() ? 'INSTALLED' : 'READY', `Install prompt completed · v${RELEASE}`);
  });

  document.addEventListener('DOMContentLoaded', () => {
    setInstallState(standalone() ? 'INSTALLED' : 'CHECKING', `ZEN Control PWA · v${RELEASE}`);
    registerServiceWorker();
  });
})();
