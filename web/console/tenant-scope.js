/*
 * vAIb-ae11 — tenant-scoped console hardening (UI side).
 *
 * The Fiduciaries tab (lists ALL tenants) and the fiduciary/app DEACTIVATION control are
 * PLATFORM-only. A tenant-scoped operator (the auto-provisioned Wix-owner has a CONCRETE,
 * non-null fiduciary_id) must NOT see them — the Fiduciaries list is a contract violation and
 * deactivation would disable the very app setup we provisioned for the tenant.
 *
 * This is defence-in-depth ONLY: the server already hard-scopes every endpoint
 * (InputProcessor.resolveTenantScope) and tenant-scopes list_fiduciaries, so even if the UI is
 * bypassed the backend denies cross-tenant access and the Fiduciaries list returns exactly the
 * caller's own tenant. Hiding the controls keeps the tenant console clean and non-confusing.
 *
 * Discriminator: a tenant operator has a concrete fiduciary_id in localStorage; the PLATFORM
 * admin has the all-zeros sentinel (or none).
 */
(function () {
  var PLATFORM_FID = '00000000-0000-0000-0000-000000000000';
  function isTenantScoped() {
    var fid = (localStorage.getItem('fiduciary_id') || '').trim();
    // Tenant-scoped iff a concrete, non-sentinel fiduciary is bound to this operator.
    return fid !== '' && fid !== PLATFORM_FID;
  }

  function applyTenantScopeUi() {
    if (!isTenantScoped()) return; // platform admin: leave the full platform console intact.

    // Hide the platform-only Fiduciaries tab.
    var navFid = document.getElementById('nav-fiduciaries');
    if (navFid) navFid.style.display = 'none';

    // Hide deactivation / disable / revoke controls reachable from the tenant console. These
    // are PLATFORM-admin-only (the TSI super-admin console lives OUTSIDE the Wix dashboard):
    // a Wix-dashboard site owner must not deactivate their own fiduciary/app or revoke keys.
    var selectors = [
      '[data-platform-only]',
      '#nav-fiduciaries',
      '.deactivate-fiduciary', '.delete-fiduciary',
      '.deactivate-app', '.delete-app',
      '#deactivate-app-btn', '#delete-app-btn',
      '.revoke-key', '.revoke-api-key', '#revoke-key-btn'  // platform-only (user 2026-06-21)
    ];
    selectors.forEach(function (sel) {
      document.querySelectorAll(sel).forEach(function (el) { el.style.display = 'none'; });
    });

    // Row-level controls rendered by table JS with no class hook — hide by their action text
    // (Deactivate / Revoke / Delete) so a tenant owner never sees the destructive actions.
    var KILL_TEXT = /^\s*(Deactivate|Revoke|Delete)\s*$/i;
    document.querySelectorAll('table button, table a').forEach(function (el) {
      if (KILL_TEXT.test(el.textContent || '')) el.style.display = 'none';
    });

    // Logout: a Wix-dashboard owner's identity is OWNED by Wix (they are inside manage.wix.com),
    // so there is no app-level logout. Replace it with a non-actionable "Logged in as" label.
    var owner = (localStorage.getItem('username') || localStorage.getItem('fiduciary_name') || 'Site Owner (Wix)');
    document.querySelectorAll('a, button').forEach(function (el) {
      var t = (el.textContent || '').trim();
      if (/^Logout$/i.test(t) || (el.getAttribute('onclick') || '').indexOf('handleLogout') >= 0) {
        var span = document.createElement('span');
        span.className = 'text-xs font-semibold text-gray-500';
        span.textContent = 'Logged in as ' + owner;
        if (el.parentNode) el.parentNode.replaceChild(span, el);
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', applyTenantScopeUi);
  } else {
    applyTenantScopeUi();
  }
  // Re-apply after async table renders that may inject row-level deactivate/revoke buttons.
  window.applyTenantScopeUi = applyTenantScopeUi;
  // A MutationObserver makes this robust on EVERY page without each page re-calling us: when a
  // table re-renders its rows (async fetch -> innerHTML), re-hide the platform-only controls.
  // Debounced via rAF so a burst of mutations triggers one pass. (user 2026-06-21)
  if (typeof MutationObserver !== 'undefined') {
    var scheduled = false;
    var obs = new MutationObserver(function () {
      if (scheduled) return; scheduled = true;
      (window.requestAnimationFrame || window.setTimeout)(function () {
        scheduled = false; applyTenantScopeUi();
      }, 0);
    });
    var start = function () { obs.observe(document.body, { childList: true, subtree: true }); };
    if (document.body) start();
    else document.addEventListener('DOMContentLoaded', start);
  }
})();
