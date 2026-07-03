/*
 * vAIb-83bu — shared console auth-failure guard (stop the SILENT blank dashboard).
 *
 * THE BUG this fixes: the console pages read AUTH_TOKEN = localStorage.getItem('authToken')
 * and send `Authorization: Bearer <token>` on every /api call. When the token is missing or
 * expired the backend returns 401 with an ERROR-OBJECT shape — {error:"Unauthorized",
 * message:"Authentication failed"} — NOT {status:401}. The pages only checked
 * `data.status === 401`, which never matched that shape, so `data.success && data.metrics`
 * was false and the metric cards silently stayed "--" / "Fetching logs…". A missing/invalid
 * token must be OBVIOUS, not silent.
 *
 * This helper centralises the check so every page can guard uniformly:
 *   window.ConsoleAuth.isAuthFailure(response, data) -> true on ANY auth failure:
 *     - a non-2xx HTTP response (covers the fabric proxy's 401/403/503 flat error), OR
 *     - data.error === "Unauthorized" (the CMS/proxy error-object shape), OR
 *     - data.status === 401 (the legacy shape the pages already handled), OR
 *     - a missing token in the first place (guarded at the call sites via requireToken()).
 *   window.ConsoleAuth.showSessionExpired(msg?) -> renders a clear, dismissable
 *     "Session expired — please log in again" banner with a re-login path, replacing the
 *     stuck "--"/"Fetching logs…" placeholders, and stops further silent retries.
 *   window.ConsoleAuth.requireToken() -> false + banner if authToken is absent/empty.
 *   window.ConsoleAuth.guard(response, data) -> true (and shows the banner) if this was an
 *     auth failure; the caller should `return` when it returns true.
 *
 * RE-LOGIN PATH: in the Wix-embedded panel the fix is to RELOAD the launch (the owner-gated
 * /cms/launch re-mints a fresh operator JWT + reseeds authToken), so we reload the top frame.
 * In the direct/standalone console we send the operator to the login page. We pick the path
 * off the same server-set marker tenant-scope.js uses (localStorage.wix_embedded) plus the
 * framed test — fail-safe: if unsure, offer BOTH ("Reload" and "Log in").
 */
(function () {
  function isFramed() {
    try { return window.self !== window.top; }
    catch (e) { return true; }
  }
  function isWixEmbedded() {
    // Prefer the shared detector if tenant-scope.js loaded; else replicate its rule.
    if (typeof window.isWixEmbedded === 'function') return window.isWixEmbedded();
    if ((localStorage.getItem('wix_embedded') || '') === '1') return true;
    var u = (localStorage.getItem('username') || '').trim();
    return isFramed() && /^Site Owner \(Wix\)\s+[0-9a-f-]{8,}/i.test(u);
  }

  function isAuthFailure(response, data) {
    // Non-2xx HTTP (covers the fabric proxy's flat 401/403/503 and any CMS 401).
    if (response && typeof response.ok === 'boolean' && !response.ok) return true;
    if (response && typeof response.status === 'number' && response.status === 401) return true;
    if (!data || typeof data !== 'object') return false;
    // The error-object shape the pages missed, plus the legacy {status:401} shape.
    if (String(data.error || '').toLowerCase() === 'unauthorized') return true;
    if (data.status === 401) return true;
    var msg = String(data.message || '').toLowerCase();
    if (msg.indexOf('authentication failed') >= 0 || msg.indexOf('unauthorized') >= 0) return true;
    return false;
  }

  var _shown = false;
  function showSessionExpired(msg) {
    if (_shown) return;                 // one banner; stop the silent-retry churn.
    _shown = true;
    var embedded = isWixEmbedded();
    var text = msg || 'Session expired — please log in again.';
    var bar = document.createElement('div');
    bar.setAttribute('role', 'alert');
    bar.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:2000;background:#b91c1c;' +
      'color:#fff;padding:12px 16px;font:600 14px/1.4 system-ui,sans-serif;' +
      'display:flex;align-items:center;gap:12px;box-shadow:0 2px 8px rgba(0,0,0,.25)';
    var span = document.createElement('span');
    span.style.flex = '1';
    span.textContent = text;           // textContent => no HTML injection.
    bar.appendChild(span);

    // Re-login action(s). Embedded => reload the top frame (re-mints via /cms/launch).
    // Direct => go to the operator login page. When unsure, offer both.
    function mkBtn(label, onClick) {
      var b = document.createElement('button');
      b.textContent = label;
      b.style.cssText = 'background:#fff;color:#b91c1c;border:0;border-radius:6px;' +
        'padding:6px 12px;font:700 13px system-ui,sans-serif;cursor:pointer';
      b.addEventListener('click', onClick);
      return b;
    }
    if (embedded) {
      bar.appendChild(mkBtn('Reload', function () {
        try { (window.top || window).location.reload(); } catch (e) { window.location.reload(); }
      }));
    } else {
      bar.appendChild(mkBtn('Log in', function () {
        // Clear the stale session then send to the login page (relative to the console root).
        try { localStorage.clear(); } catch (e) {}
        // Pages live at .../console/<area>/<page>.html; the operator login is at the root.
        var p = location.pathname;
        var i = p.lastIndexOf('/console/');
        var base = i >= 0 ? p.slice(0, i + '/console/'.length) : '../';
        window.location.href = base + 'index.html';
      }));
    }
    (document.body || document.documentElement).appendChild(bar);
    // Nudge the body down so the banner never overlaps the first row of content.
    try { document.body.style.paddingTop = (parseInt(getComputedStyle(document.body).paddingTop || '0', 10) + 48) + 'px'; } catch (e) {}
  }

  function requireToken() {
    var t = (localStorage.getItem('authToken') || '').trim();
    if (!t || t === 'null' || t === 'undefined') {
      showSessionExpired('Not signed in — please log in again.');
      return false;
    }
    return true;
  }

  function guard(response, data) {
    if (isAuthFailure(response, data)) {
      showSessionExpired();
      return true;
    }
    return false;
  }

  window.ConsoleAuth = {
    isAuthFailure: isAuthFailure,
    showSessionExpired: showSessionExpired,
    requireToken: requireToken,
    guard: guard
  };
})();
