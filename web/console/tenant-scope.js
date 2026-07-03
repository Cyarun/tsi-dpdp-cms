/*
 * vAIb-ae11 — tenant-scoped console hardening (UI side).
 * vAIb-83bu — context-aware account controls (direct vs Wix-embedded).
 *
 * TWO independent concerns, TWO independent discriminators:
 *
 *  (1) PLATFORM-only controls (Fiduciaries tab / fiduciary+app DEACTIVATION / key REVOKE).
 *      Discriminator: isTenantScoped() — a tenant operator has a CONCRETE, non-null
 *      fiduciary_id; the PLATFORM admin has the all-zeros sentinel (or none). A tenant
 *      operator must NOT see these (cross-tenant list = contract violation; deactivation
 *      would disable the very app we provisioned). This is defence-in-depth ONLY: the
 *      server already hard-scopes every endpoint (InputProcessor.resolveTenantScope) and
 *      tenant-scopes list_fiduciaries, so a bypass still denies cross-tenant access.
 *
 *  (2) ACCOUNT controls (Logout / Change Password / integration management).
 *      Discriminator: isWixEmbedded() — is this console running INSIDE the Wix dashboard
 *      panel? A Wix owner's identity is OWNED by Wix (they are inside manage.wix.com);
 *      onboarding + decommission are AUTOMATIC via app install/uninstall. So in the
 *      Wix-embedded view we HIDE logout/change-password entirely — an in-panel logout or
 *      credential change would EVICT/BREAK the signed-instance integration. In the DIRECT
 *      (standalone) view we SHOW the full account menu (logout + change password), because
 *      a direct operator authenticated with a password and must be able to sign out /
 *      rotate it.
 *
 *      WHY a SEPARATE discriminator (not isTenantScoped): a DIRECT tenant-operator login
 *      ALSO has a concrete fiduciary_id, so the old code (which hid logout whenever
 *      tenant-scoped) wrongly hid logout on the direct console too — the reported
 *      "no visible Logout on the direct admin dashboard" bug. Account-control visibility
 *      keys off EMBEDDING, not scope.
 *
 * CONTEXT DETECTION (isWixEmbedded) — non-spoofable toward the dangerous direction:
 *   The risk is ASYMMETRIC. Exposing logout/credential controls in the Wix panel could
 *   evict the integration; hiding them on a direct login is merely an inconvenience. So we
 *   FAIL SAFE TOWARD HIDING: treat the session as Wix-embedded if EITHER
 *     (a) the SERVER-set marker localStorage.wix_embedded === '1'  — AUTHORITATIVE. Only
 *         the fabric /cms/launch landing sets it, and only AFTER owner-gating the
 *         Wix-signed instance server-side (console.py _launch_html). A direct login never
 *         passes through that landing and platform/login.html actively clears it. A client
 *         cannot forge a Wix session by clearing the marker — clearing it only reveals the
 *         corroborating iframe test below, which still holds for a real embed.
 *   OR
 *     (b) the page is FRAMED (window.self !== window.top) AND the operator is the Wix owner
 *         (username matches the "Site Owner (Wix) <uuid>" pattern the launch mints). The
 *         Wix panel ALWAYS frames the console; a direct login is top-level. This corroborates
 *         (a) and covers a session whose marker was dropped, so the marker can only ever
 *         HIDE controls, never be removed to EXPOSE them in a genuine embed.
 *   The two signals are combined with OR precisely so neither can be individually spoofed to
 *   EXPOSE account controls inside the Wix panel. (Pure iframe-detection alone is spoofable
 *   and is therefore never the SOLE positive signal for exposing anything — it only ever
 *   pushes toward HIDING.)
 */
(function () {
  var PLATFORM_FID = '00000000-0000-0000-0000-000000000000';
  // "Site Owner (Wix) <uuid>" — the username the owner-gated launch mints (dashboard.html:318).
  var WIX_OWNER_RE = /^Site Owner \(Wix\)\s+[0-9a-f-]{8,}/i;

  function isTenantScoped() {
    var fid = (localStorage.getItem('fiduciary_id') || '').trim();
    // Tenant-scoped iff a concrete, non-sentinel fiduciary is bound to this operator.
    return fid !== '' && fid !== PLATFORM_FID;
  }

  // Is the page rendered inside a (cross-origin or same-origin) frame? The Wix panel frames
  // the console; a direct login is top-level. Wrapped because a cross-origin ancestor can make
  // even window.top access throw — a throw means we ARE framed, so treat it as embedded.
  function isFramed() {
    try { return window.self !== window.top; }
    catch (e) { return true; }
  }

  function isWixOwnerUser() {
    var u = (localStorage.getItem('username') || '').trim();
    return WIX_OWNER_RE.test(u);
  }

  // FAIL-SAFE-TOWARD-HIDING context detector (see header). Authoritative server marker OR
  // (framed AND Wix-owner) => Wix-embedded => hide account controls.
  function isWixEmbedded() {
    if ((localStorage.getItem('wix_embedded') || '') === '1') return true;
    if (isFramed() && isWixOwnerUser()) return true;
    return false;
  }

  function applyTenantScopeUi() {
    var embedded = isWixEmbedded();

    // ---- (2) ACCOUNT controls: keyed off EMBEDDING, applied first so a stale marker never
    //          leaves an actionable Logout in the Wix panel. ------------------------------
    if (embedded) {
      // Wix-embedded: the Wix session IS the identity — no app-level logout / credential
      // change. Replace any Logout link with a non-actionable "Logged in as" label and hide
      // any change-password control. (Onboarding/decommission is AUTOMATIC via app install/
      // uninstall; an in-panel logout would evict the signed-instance integration.)
      var owner = (localStorage.getItem('fiduciary_name') || localStorage.getItem('username') || 'Site Owner (Wix)');
      document.querySelectorAll('a, button').forEach(function (el) {
        var t = (el.textContent || '').trim();
        var onclick = (el.getAttribute('onclick') || '');
        if (/^Logout$/i.test(t) || onclick.indexOf('handleLogout') >= 0) {
          var span = document.createElement('span');
          span.className = 'text-xs font-semibold text-gray-500';
          span.textContent = 'Logged in as ' + owner;
          if (el.parentNode) el.parentNode.replaceChild(span, el);
        }
      });
      // Hide any Change-Password / account-menu control in the embedded panel.
      ['[data-account-control]', '#change-password-btn', '.change-password',
       '#account-menu', '.account-menu'].forEach(function (sel) {
        document.querySelectorAll(sel).forEach(function (el) { el.style.display = 'none'; });
      });
    } else {
      // DIRECT (standalone) login: SHOW the account controls. Reveal any account-menu markup
      // pages ship hidden-by-default (so it never flashes in the embedded panel), and ensure
      // the Logout link is visible/actionable. We DO NOT touch the Logout link here — leaving
      // it exactly as the page authored it fixes the "no visible Logout on direct" report.
      document.querySelectorAll('[data-account-control]').forEach(function (el) {
        el.style.display = '';
      });
    }

    // ---- (1) PLATFORM-only controls: keyed off SCOPE (unchanged behaviour). --------------
    if (!isTenantScoped()) return; // platform admin: leave the full platform console intact.

    // Hide the platform-only Fiduciaries tab.
    var navFid = document.getElementById('nav-fiduciaries');
    if (navFid) navFid.style.display = 'none';

    // Hide deactivation / disable / revoke controls reachable from the tenant console. These
    // are PLATFORM-admin-only (the TSI super-admin console lives OUTSIDE the Wix dashboard):
    // a tenant site owner must not deactivate their own fiduciary/app or revoke keys.
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
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', applyTenantScopeUi);
  } else {
    applyTenantScopeUi();
  }
  // Expose helpers so pages can conditionally render (e.g. a Change-Password menu on direct only).
  window.applyTenantScopeUi = applyTenantScopeUi;
  window.isWixEmbedded = isWixEmbedded;
  // A MutationObserver makes this robust on EVERY page without each page re-calling us: when a
  // table re-renders its rows (async fetch -> innerHTML), re-hide the platform-only controls
  // AND re-neutralise any late-rendered Logout in the embedded panel. Debounced via rAF so a
  // burst of mutations triggers one pass. (user 2026-06-21)
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
