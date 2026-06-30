-- 09_data_point_catalog.sql
-- vAIb (mydata-ui P0) — Canonical DATA-POINT CATALOG: the single source of truth for
-- "what personal data can exist" across the DPDPA.center platform.
--
-- WHY: Every downstream surface (RoPA, Privacy Policy, My-Data toggles) needs a
-- stable, human-readable vocabulary of data-point types. Without a single reference
-- table, each service maintains its own ad-hoc list and they diverge. This table
-- is the authoritative catalog that all services REFERENCE — it defines the universe
-- of data-point kinds, their sensitivity tier, and display labels.
--
-- WHAT: One row per data-point KIND (identified by a stable string key, e.g. 'email',
-- 'dob', 'health_note'). NOT per-tenant — the catalog is global reference data, the
-- same for all fiduciaries. fiduciary_id is intentionally absent. Per-tenant
-- configuration (which data points a fiduciary actually processes) lives in a
-- separate mapping table (future P1).
--
-- SEED: rows are the union of existing fabric _CATEGORY_DETAIL entries and the
-- categories already used by RoPA activities, so nothing in the existing platform
-- regresses. INSERT ... ON CONFLICT (id) DO NOTHING makes re-running this
-- migration idempotent.

-- --- Data-point catalog (global reference, NOT per-tenant) ----------------------
CREATE TABLE IF NOT EXISTS data_point_catalog (
    -- Stable string key referenced by RoPA, Policy, My-Data toggles, etc.
    -- e.g. 'email', 'dob', 'health_note'. NOT a uuid — string ids are
    -- self-documenting and survive database restores without UUID mapping.
    id          TEXT PRIMARY KEY,
    -- Human-readable display label shown in UI surfaces.
    label       TEXT NOT NULL,
    -- Grouping category for UI organisation and filtering.
    -- Values: identity / contact / address / financial / account /
    --         behavioral / special_category / content / preferences / profile
    category    TEXT NOT NULL,
    -- DPDPA sensitivity tier. 'sensitive' data requires additional safeguards
    -- (consent, DPO sign-off) under the Act.
    sensitivity TEXT NOT NULL DEFAULT 'standard'
        CHECK (sensitivity IN ('standard', 'sensitive')),
    -- Optional free-text description for operator-facing UI tooltips.
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index for the most common query pattern: list by category then by id.
CREATE INDEX IF NOT EXISTS idx_data_point_catalog_category
    ON data_point_catalog (category, id);

-- Comment the table and key columns for pg_dump / introspection tooling.
COMMENT ON TABLE  data_point_catalog              IS 'Global reference catalog of personal-data-point kinds (DPDPA.center P0). One row per kind; shared across all tenants.';
COMMENT ON COLUMN data_point_catalog.id           IS 'Stable string key (e.g. email, dob) referenced by RoPA/Policy/My-Data.';
COMMENT ON COLUMN data_point_catalog.sensitivity  IS 'standard = ordinary personal data; sensitive = special-category data under DPDPA requiring extra safeguards.';

-- --- Seed rows ------------------------------------------------------------------
-- Union of fabric _CATEGORY_DETAIL entries + RoPA activity categories already in
-- production. ON CONFLICT (id) DO NOTHING makes this idempotent across re-runs.
INSERT INTO data_point_catalog (id, label, category, sensitivity, description)
VALUES
    ('identity',              'Identity',                   'identity',         'standard',  'Name and other identifying details.'),
    ('contact',               'Contact information',        'contact',          'standard',  'Email, phone, and contact details.'),
    ('address',               'Address',                    'address',          'standard',  'Postal / delivery address details.'),
    ('billing_address',       'Billing address',            'address',          'standard',  'Billing address for payments.'),
    ('shipping_address',      'Shipping address',           'address',          'standard',  'Delivery / shipping address.'),
    ('account_credentials',   'Account credentials',        'account',          'standard',  'Sign-in identifiers for accounts.'),
    ('purchase_history',      'Purchase history',           'behavioral',       'standard',  'Records of orders and purchases.'),
    ('payment_metadata',      'Payment information',        'financial',        'sensitive', 'Payment-related transaction data.'),
    ('appointment_history',   'Appointment history',        'behavioral',       'standard',  'Bookings and appointment records.'),
    ('message_content',       'Messages',                   'content',          'standard',  'Customer conversation content.'),
    ('loyalty_balance',       'Loyalty balance',            'behavioral',       'standard',  'Loyalty points and rewards balance.'),
    ('transaction_history',   'Transaction history',        'behavioral',       'standard',  'Loyalty / rewards transactions.'),
    ('review_content',        'Reviews',                    'content',          'standard',  'Customer review and rating content.'),
    ('marketing_labels',      'Marketing preferences',      'preferences',      'standard',  'Marketing audience labels.'),
    ('profile',               'Profile',                    'profile',          'standard',  'Profile attributes you provide.'),
    ('form_submissions',      'Form submissions',           'content',          'standard',  'Information submitted through website forms.'),
    ('media_content',         'Photo & media',              'special_category', 'sensitive', 'Photos, images, and media (e.g. before/after photos).'),
    ('acknowledgment_records','Acknowledgments & waivers',  'content',          'standard',  'Signed waivers and acknowledgments.'),
    ('special_category',      'Sensitive data',             'special_category', 'sensitive', 'Data needing extra protection (health, government IDs, biometrics).'),
    ('behavioral',            'Behavioral data',            'behavioral',       'standard',  'Usage and interaction patterns.'),
    ('device_info',           'Device information',         'behavioral',       'standard',  'Device and technical metadata.')
ON CONFLICT (id) DO NOTHING;
