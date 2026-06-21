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

    // Hide any deactivation / disable controls (fiduciary or app) reachable from the tenant
    // console. Matched by a stable data attribute and common control ids/classes.
    var selectors = [
      '[data-platform-only]',
      '#nav-fiduciaries',
      '.deactivate-fiduciary', '.delete-fiduciary',
      '.deactivate-app', '.delete-app',
      '#deactivate-app-btn', '#delete-app-btn'
    ];
    selectors.forEach(function (sel) {
      document.querySelectorAll(sel).forEach(function (el) { el.style.display = 'none'; });
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', applyTenantScopeUi);
  } else {
    applyTenantScopeUi();
  }
  // Re-apply after async table renders that may inject row-level deactivate buttons.
  window.applyTenantScopeUi = applyTenantScopeUi;
})();
