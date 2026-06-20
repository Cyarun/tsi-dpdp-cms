/**
 * TSI DPDP CMS — Data Principal Self-Service Portal
 * Shared session management and API utilities.
 * All session state is stored in sessionStorage (auto-clears on tab close).
 */

// vAIb-7fic: route the data-principal /api/v1/client/* calls THROUGH fabric's
// PRINCIPAL-scoped console proxy (the Wix-app thin security gateway), instead of the
// CMS directly. apiCall('/api/v1/client/consent', ...) -> this base + that path ->
// fabric /v1/console/cms/client-api/api/v1/client/consent (the proxy verifies the
// member countersign + forwards the principal Bearer token, and the CMS sees
// /api/v1/client/consent). When this page is served by fabric (embedded in the Wix
// My Data widget) the widget injects the session via postMessage (see the
// vaib-principal-session bootstrap in dashboard.html) so no second login is needed.
//
// STANDALONE fallback: if the page is opened directly (not via fabric / not on the
// docs.cynorsense.com origin), keep the legacy same-origin base so a developer can
// still load it against a local CMS. The fabric base is used ONLY when the page is
// actually served from the fabric origin.
const PORTAL_BASE_URL = (function () {
    try {
        if (location.hostname === 'docs.cynorsense.com') {
            return 'https://docs.cynorsense.com/vaib/fabric/console/cms/client-api';
        }
    } catch (e) { /* non-browser / sandboxed -> fall through */ }
    return 'http://localhost:8080';
})();

const SESSION_KEYS = {
    token:          'pp_token',
    userId:         'pp_user_id',
    fiduciaryId:    'pp_fiduciary_id',
    fiduciaryName:  'pp_fiduciary_name',
    policies:       'pp_policies',  // JSON array of { policy_id, version, jurisdiction, title }
    // The Wix member countersign (instance + member_sig + member_ts), carried so EVERY
    // /api/v1/client/* call can re-present it to the fabric proxy. Fabric requires the
    // countersign per-call AND binds it to the Bearer's principal (cross-principal IDOR
    // guard, vAIb-7fic SEC Finding 1) — so the principal proves identity BOTH ways on
    // every call: the CMS-signed Bearer + the fabric-verified Wix countersign.
    instance:       'pp_instance',
    memberSig:      'pp_member_sig',
    memberTs:       'pp_member_ts'
};

function getSession() {
    const token = sessionStorage.getItem(SESSION_KEYS.token);
    if (!token) return null;
    return {
        token:         token,
        userId:        sessionStorage.getItem(SESSION_KEYS.userId),
        fiduciaryId:   sessionStorage.getItem(SESSION_KEYS.fiduciaryId),
        fiduciaryName: sessionStorage.getItem(SESSION_KEYS.fiduciaryName),
        policies:      getSessionPolicies(),
        instance:      sessionStorage.getItem(SESSION_KEYS.instance),
        memberSig:     sessionStorage.getItem(SESSION_KEYS.memberSig),
        memberTs:      sessionStorage.getItem(SESSION_KEYS.memberTs)
    };
}

function saveSession(data) {
    sessionStorage.setItem(SESSION_KEYS.token,         data.token          || '');
    sessionStorage.setItem(SESSION_KEYS.userId,        data.user_id        || '');
    sessionStorage.setItem(SESSION_KEYS.fiduciaryId,   data.fiduciary_id   || '');
    sessionStorage.setItem(SESSION_KEYS.fiduciaryName, data.fiduciary_name || '');
    sessionStorage.setItem(SESSION_KEYS.policies,      JSON.stringify(data.policies || []));
    // Countersign material injected by the widget alongside the principal session.
    sessionStorage.setItem(SESSION_KEYS.instance,      data.instance       || '');
    sessionStorage.setItem(SESSION_KEYS.memberSig,     data.member_sig     || '');
    sessionStorage.setItem(SESSION_KEYS.memberTs,      data.member_ts      || '');
}

function getSessionPolicies() {
    try { return JSON.parse(sessionStorage.getItem(SESSION_KEYS.policies) || '[]'); }
    catch { return []; }
}

function getPolicyTitle(policyId) {
    const policies = getSessionPolicies();
    const match = policies.find(p => p.policy_id === policyId);
    return match ? match.title : policyId;
}

function clearSession() {
    Object.values(SESSION_KEYS).forEach(k => sessionStorage.removeItem(k));
}

function requireAuth() {
    const session = getSession();
    if (!session) {
        window.location.href = 'index.html';
        return null;
    }
    return session;
}

async function apiCall(path, func, bodyExtra) {
    const session = getSession();
    const headers = {
        'Content-Type': 'application/json; charset=UTF-8',
        'Accept': 'application/json; charset=UTF-8'
    };
    if (session) {
        headers['Authorization'] = 'Bearer ' + session.token;
    }
    // Re-present the Wix member countersign on EVERY call so the fabric proxy can
    // verify it (per-call) AND bind it to the Bearer's principal. The proxy STRIPS
    // these before forwarding upstream, so the CMS never sees them.
    const cs = session
        ? { instance: session.instance, member_sig: session.memberSig, member_ts: session.memberTs }
        : {};
    const body = JSON.stringify({ _func: func, ...cs, ...bodyExtra });
    try {
        const res = await fetch(PORTAL_BASE_URL + path, { method: 'POST', headers, body });
        if (res.status === 401) {
            clearSession();
            window.location.href = 'index.html';
            return null;
        }
        return await res.json();
    } catch (e) {
        console.error('Portal API error:', e);
        return null;
    }
}

async function publicApiCall(path, func, bodyExtra) {
    const headers = {
        'Content-Type': 'application/json; charset=UTF-8',
        'Accept': 'application/json; charset=UTF-8'
    };
    const body = JSON.stringify({ _func: func, ...bodyExtra });
    const res = await fetch(PORTAL_BASE_URL + path, { method: 'POST', headers, body });
    return await res.json();
}

function esc(s) {
    if (s == null) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
}

function formatTimestamp(iso) {
    return iso ? new Date(iso).toLocaleString() : 'N/A';
}

function getStatusBadge(status) {
    const s = (status || '').toUpperCase();
    const colors = {
        'ACTIVE':             'background:#f0fdf4;color:#15803d;border-color:#bbf7d0',
        'CONSENT_GIVEN':      'background:#f0fdf4;color:#15803d;border-color:#bbf7d0',
        'RESOLVED':           'background:#f0fdf4;color:#15803d;border-color:#bbf7d0',
        'IN_PROGRESS':        'background:#fefce8;color:#a16207;border-color:#fde68a',
        'PENDING_DPO_REVIEW': 'background:#fefce8;color:#a16207;border-color:#fde68a',
        'WITHDRAWN':            'background:#fef2f2;color:#b91c1c;border-color:#fecaca',
        'CONSENT_WITHDRAWN':    'background:#fef2f2;color:#b91c1c;border-color:#fecaca',
        'PARTIALLY WITHDRAWN':  'background:#fefce8;color:#a16207;border-color:#fde68a',
        'ERASURE_REQUEST':      'background:#fef2f2;color:#b91c1c;border-color:#fecaca'
    };
    const style = colors[s] || 'background:#f8fafc;color:#475569;border-color:#e2e8f0';
    return `<span style="font-size:0.65rem;padding:2px 8px;border-radius:9999px;text-transform:uppercase;font-weight:800;border:1px solid;${style}">${esc(s.replace(/_/g, ' '))}</span>`;
}

function resolvePolicyContent(data) {
    let content = data.policy_content || data;
    if (typeof content === 'string') {
        try { content = JSON.parse(content); } catch (e) {}
    }
    return content;
}

function getPreferredLanguage(policyMap) {
    const lang = (document.documentElement.lang || navigator.language || 'en').toLowerCase();
    const available = Object.keys(policyMap);
    if (available.includes(lang)) return lang;
    const base = lang.split('-')[0];
    if (available.includes(base)) return base;
    return available.includes('en') ? 'en' : available[0];
}
