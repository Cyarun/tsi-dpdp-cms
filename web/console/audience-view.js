/*
 * vAIb-kyog — AUDIENCE-BASED CLEAN VIEWS (shared label dictionary + audience gate).
 *
 * THREE audiences see the SAME data differently:
 *   1. TENANT  (Wix-owner ADMIN + fiduciary DPO, a CONCRETE fiduciary)  -> CLEAN human-readable
 *      ONLY. Real app/field/activity names, data categories as labels, the policy's human title.
 *      ABSOLUTELY NO uuids / policy_id / fiduciary_id / entry_id / version-author uuid / DPO ID /
 *      raw discovery JSON / machine-enum values.
 *   2. TSI STAFF (platform roles SUPER_ADMIN/ONBOARDING_MANAGER/SUPPORT_ASSISTANT, NULL fiduciary)
 *      -> FULL RAW incl. every ID + raw discovery (to debug/help the tenant).
 *   3. DATA PRINCIPAL (My-Data) -> handled separately under web/rights (own consents/rights only).
 *
 * DISCRIMINATOR (server-mirrored): the tenant operator carries a CONCRETE, non-sentinel
 * fiduciary_id in localStorage; the PLATFORM admin carries the all-zeros sentinel (or none).
 * This is the SAME NULL-vs-concrete discriminator the server uses
 * (InputProcessor.PLATFORM_ADMIN_FID / resolveTenantScope). UI-side this is presentation-only:
 * the backend still hard-scopes every endpoint, so a tampered localStorage cannot widen ACCESS —
 * only what labels-vs-raw a viewer is shown. Default: CLEAN (fail closed toward less exposure).
 */
(function (global) {
  'use strict';

  var PLATFORM_FID = '00000000-0000-0000-0000-000000000000';
  var UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
  var POLICY_ID_RE = /^dpdp-[0-9a-f]{6,}$/i; // generated policy ids, e.g. dpdp-104b17c3

  // ── Audience gate ──────────────────────────────────────────────────────────
  // TENANT (clean) iff a concrete, non-sentinel fiduciary is bound. Anything else
  // (platform sentinel OR no fiduciary at all = platform/TSI-staff console) -> RAW.
  function isTenantView() {
    var fid = (localStorage.getItem('fiduciary_id') || '').trim();
    return fid !== '' && fid !== PLATFORM_FID;
  }
  // TSI staff = the inverse. A concrete fiduciary is NEVER staff.
  function isStaffView() { return !isTenantView(); }

  // ── Label dictionary (machine -> human) ─────────────────────────────────────
  // Known DPDPA vocabulary. UNKNOWN values fall through to humanize() so a new
  // discovery enum never renders as a raw token to the tenant (graceful, not blank).
  var PURPOSES = {
    support_messaging:   'Support & messaging',
    customer_support:    'Customer support',
    service_delivery:    'Service delivery',
    service_provision:   'Service provision',
    order_fulfillment:   'Order fulfilment',
    order_fulfilment:    'Order fulfilment',
    appointment_booking: 'Appointment booking',
    bookings:            'Bookings & appointments',
    payments:            'Payments & billing',
    billing:             'Billing',
    marketing:           'Marketing & promotions',
    email_marketing:     'Email marketing',
    analytics:           'Analytics & insights',
    personalization:     'Personalisation',
    personalisation:     'Personalisation',
    account_management:  'Account management',
    membership:          'Membership',
    newsletter:          'Newsletter',
    contact_form:        'Contact requests',
    reviews:             'Reviews & feedback',
    shipping:            'Shipping & delivery',
    fraud_prevention:    'Fraud prevention',
    legal_compliance:    'Legal compliance',
    security:            'Security'
  };

  var DATA_CATEGORIES = {
    communications:       'Communications',
    contact_info:         'Contact details',
    contact_details:      'Contact details',
    identity:             'Identity details',
    identity_data:        'Identity details',
    name:                 'Name',
    email:                'Email address',
    phone:                'Phone number',
    address:              'Postal address',
    financial:            'Financial details',
    financial_data:       'Financial details',
    payment_info:         'Payment details',
    transaction_data:     'Transaction history',
    order_history:        'Order history',
    appointment_data:     'Appointment details',
    booking_data:         'Booking details',
    usage_data:           'Usage & activity',
    behavioural_data:     'Behavioural data',
    behavioral_data:      'Behavioural data',
    location:             'Location',
    location_data:        'Location',
    device_data:          'Device & technical',
    technical_data:       'Device & technical',
    preferences:          'Preferences',
    marketing_data:       'Marketing preferences',
    health_data:          'Health information',
    demographic_data:     'Demographic details'
  };

  // Data SUBJECT (data principal) categories — who the data is about.
  var DATA_SUBJECTS = {
    data_principals:  'Data principals',
    data_subjects:    'Data principals',
    customers:        'Customers',
    members:          'Members',
    visitors:         'Visitors',
    subscribers:      'Subscribers',
    employees:        'Employees',
    prospects:        'Prospective customers',
    leads:            'Leads',
    children:         'Children',
    guardians:        'Parents / guardians',
    vendors:          'Vendors',
    contacts:         'Contacts'
  };

  var LEGAL_BASIS = {
    consent:          'Consent',
    legitimate_use:   'Legitimate use',
    legitimate_uses:  'Legitimate use',
    legal_obligation: 'Legal obligation',
    contract:         'Contractual necessity',
    vital_interest:   'Vital interest',
    public_interest:  'Public interest',
    employment:       'Employment'
  };

  var RETENTION_EVENTS = {
    COLLECTION: 'from collection',
    CESSATION:  'after account closure',
    collection: 'from collection',
    cessation:  'after account closure'
  };

  // Internal source keys -> the real Wix app display name the tenant recognises.
  var APP_NAMES = {
    wix_bookings: 'Wix Bookings',
    wixbookings:  'Wix Bookings',
    bookings:     'Wix Bookings',
    wix_stores:   'Wix Stores',
    wixstores:    'Wix Stores',
    stores:       'Wix Stores',
    wix_forms:    'Wix Forms',
    wixforms:     'Wix Forms',
    forms:        'Wix Forms',
    wix_events:   'Wix Events',
    events:       'Wix Events',
    wix_blog:     'Wix Blog',
    blog:         'Wix Blog',
    wix_members:  'Wix Members',
    members_area: 'Members Area',
    wix_chat:     'Wix Chat',
    chat:         'Wix Chat',
    contacts:     'Wix Contacts',
    crm:          'Wix CRM',
    pricing_plans:'Pricing Plans',
    wix_groups:   'Wix Groups',
    newsletter:   'Wix Email Marketing',
    email_marketing: 'Wix Email Marketing'
  };

  // ── Core humanizer ──────────────────────────────────────────────────────────
  // Title-cases a snake/kebab token. The graceful fallback for any value not in a
  // dictionary, so the tenant NEVER sees a raw machine token even for new enums.
  function humanize(token) {
    if (token == null) return '';
    var s = String(token).trim();
    if (s === '') return '';
    // Never let a raw uuid/policy-id slip through humanize.
    if (UUID_RE.test(s) || POLICY_ID_RE.test(s)) return '';
    return s
      .replace(/[_-]+/g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
      .replace(/\b\w/g, function (c) { return c.toUpperCase(); });
  }

  function lookup(dict, value, fallbackToHumanize) {
    if (value == null) return '';
    var key = String(value).trim();
    if (key === '') return '';
    var lc = key.toLowerCase();
    if (Object.prototype.hasOwnProperty.call(dict, key)) return dict[key];
    if (Object.prototype.hasOwnProperty.call(dict, lc)) return dict[lc];
    return fallbackToHumanize === false ? '' : humanize(key);
  }

  function purpose(v)      { return lookup(PURPOSES, v); }
  function dataCategory(v) { return lookup(DATA_CATEGORIES, v); }
  function dataSubject(v)  { return lookup(DATA_SUBJECTS, v); }
  function legalBasis(v)   { return lookup(LEGAL_BASIS, v); }
  function appName(v)      { return lookup(APP_NAMES, v); }

  function retentionEvent(v) {
    if (v == null || String(v).trim() === '') return '';
    var key = String(v).trim();
    if (Object.prototype.hasOwnProperty.call(RETENTION_EVENTS, key)) return RETENTION_EVENTS[key];
    if (Object.prototype.hasOwnProperty.call(RETENTION_EVENTS, key.toUpperCase())) return RETENTION_EVENTS[key.toUpperCase()];
    return humanize(key);
  }

  // ── Array helpers ────────────────────────────────────────────────────────────
  function parseArr(val) {
    if (!val) return [];
    if (Array.isArray(val)) return val;
    try { var p = JSON.parse(val); return Array.isArray(p) ? p : [p]; } catch (e) { return [String(val)]; }
  }

  // Map an array of machine values to human labels via a mapper fn, dropping blanks.
  function labels(val, mapper) {
    return parseArr(val).map(mapper).filter(function (x) { return x && x !== ''; });
  }

  // Join labels for plain-text display ('—' when empty).
  function labelList(val, mapper) {
    var l = labels(val, mapper);
    return l.length ? l.join(', ') : '—';
  }

  // ── HTML-escape (defence-in-depth for any value we inject) ────────────────────
  function esc(s) {
    if (s == null) return '';
    return String(s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // Render an array of machine values as escaped human-readable chips.
  function chips(val, mapper, chipClass) {
    var l = labels(val, mapper);
    if (!l.length) return '<span class="text-slate-400 text-xs">None</span>';
    var cls = chipClass || 'inline-block bg-teal-50 text-teal-800 text-[11px] font-semibold px-2 py-0.5 rounded-full mr-1 mb-1';
    return l.map(function (x) { return '<span class="' + cls + '">' + esc(x) + '</span>'; }).join('');
  }

  // ── Policy display ────────────────────────────────────────────────────────────
  // The tenant must see the policy's human TITLE, never the generated id (dpdp-…).
  // Pages can register a title map (policy_id -> title); when unknown, fall back to
  // a neutral 'Active policy' rather than leaking the raw id.
  var _policyTitles = {};
  function registerPolicyTitle(id, title) {
    if (id && title) _policyTitles[String(id).trim()] = String(title).trim();
  }
  function policyTitle(id) {
    if (id == null || String(id).trim() === '') return 'Active policy';
    var key = String(id).trim();
    if (_policyTitles[key]) return _policyTitles[key];
    // Tenant must never see a raw policy id; staff get the raw id elsewhere.
    return isTenantView() ? 'Active policy' : key;
  }

  // ── Reference shortener (for surfaces that legitimately need a handle) ─────────
  // Turns a uuid into a short, non-reversible-looking display reference. Used ONLY
  // where a viewer needs to *quote* their own record (e.g. a request reference),
  // never to expose internal ids to the tenant.
  function shortRef(id, prefix) {
    if (id == null || String(id).trim() === '') return '—';
    var s = String(id).replace(/-/g, '');
    return (prefix || 'REF') + '-' + s.slice(-6).toUpperCase();
  }

  // ── Public API ────────────────────────────────────────────────────────────────
  global.AudienceView = {
    PLATFORM_FID: PLATFORM_FID,
    isTenantView: isTenantView,
    isStaffView: isStaffView,
    humanize: humanize,
    purpose: purpose,
    dataCategory: dataCategory,
    dataSubject: dataSubject,
    legalBasis: legalBasis,
    appName: appName,
    retentionEvent: retentionEvent,
    parseArr: parseArr,
    labels: labels,
    labelList: labelList,
    chips: chips,
    esc: esc,
    registerPolicyTitle: registerPolicyTitle,
    policyTitle: policyTitle,
    shortRef: shortRef,
    // expose dictionaries (read-only intent) for pages that want to extend display
    _dicts: { PURPOSES: PURPOSES, DATA_CATEGORIES: DATA_CATEGORIES, DATA_SUBJECTS: DATA_SUBJECTS, LEGAL_BASIS: LEGAL_BASIS, APP_NAMES: APP_NAMES }
  };
})(window);
