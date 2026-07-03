-- 11_om_assessments.sql
-- vAIb-a0a0 (OM<->CMS bidirectional sync) — landing table for the OM-computed DPIA that
-- the native OpenMetadata DPDPA DPIA app PUSHES to the CMS (Direction 1: OM -> CMS push).
--
-- WHY: The OM DPDPA DPIA app assesses a whole customer across EVERY connector-fed
-- integration under the customer's OM Domain (wix-<instanceId>) and computes a
-- cross-source DPIA verdict (status/score/summary/gaps + per-integration roll-up). That
-- verdict is a DIFFERENT, complementary view to the CMS's OWN native RoPA DPIA (Dpia.java,
-- which assesses this tenant's RoPA rows). This table caches the LAST OM-pushed verdict so
-- the DPO console (dpia.html) can render the OpenMetadata cross-source assessment ALONGSIDE
-- the native CMS-RoPA assessment ("show both").
--
-- WHAT this records: one row per OM push event, stamping a VALUE-FREE / METADATA-ONLY DPIA
-- summary — status enum, an integer score, a markdown summary, gap CODES (jsonb), and a
-- per-integration roll-up (jsonb: [{service, platform, status, score, activities, gaps}...]).
-- NO principal PII is ever stored — only compliance metadata, counts and citations.
--
-- ISOLATION (vAIb-ae11 / vAIb-a0a0): fiduciary_id is ALWAYS the caller's OWN server-derived
-- tenant (from the OM app's api-key -> Fiduciary.getFiduciaryId), NEVER a body value that is
-- trusted blindly. One OM domain <-> one CMS fiduciary_id; a push can only write the matching
-- tenant's row. Multiple rows per tenant are intentional: the latest by assessed_at (then
-- created_at) wins on read; older rows form an audit trail of successive OM assessment runs.

-- --- OM-pushed cross-source DPIA assessments (per-tenant, append-only) ------------
CREATE TABLE IF NOT EXISTS om_assessments (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fiduciary_id     UUID NOT NULL REFERENCES fiduciaries(id),
    -- The OM Domain FQN this verdict came from (e.g. wix-104b17c3_70f). Metadata only —
    -- the tenant identifier on the OM side, kept for traceability / display. NOT authority:
    -- the authority is fiduciary_id (server-derived from the pushing api-key).
    om_domain        VARCHAR(256) NOT NULL,
    -- Overall (combined, worst-wins) compliance status: compliant / attention / non_compliant.
    dpia_status      VARCHAR(32)  NOT NULL,
    -- Overall combined compliance score 0-100.
    dpia_score       INTEGER      NOT NULL DEFAULT 0,
    -- Human-readable markdown summary of the combined verdict (already markdown-safe text
    -- produced by the OM engine; re-escaped on render). NO PII.
    dpia_summary     TEXT,
    -- Combined gap CODES + counts as JSONB (value-free gap facets, never PII). E.g.
    -- {"total_gaps": 4, "codes": ["missing_legal_basis", "missing_retention"]}.
    dpia_gaps        JSONB        NOT NULL DEFAULT '{}'::jsonb,
    -- Per-integration roll-up as JSONB: [{service, platform, status, score, activities, gaps}...].
    -- One entry per connector-fed integration under the OM Domain. Counts/statuses only.
    per_integration  JSONB        NOT NULL DEFAULT '[]'::jsonb,
    -- When the OM app performed this assessment run (OM-supplied ISO-8601; defaults to now()).
    assessed_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    -- When the CMS landed this push.
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Fast lookup: latest OM assessment for a given fiduciary, or full history in order.
CREATE INDEX IF NOT EXISTS idx_om_assessments_fid_assessed
    ON om_assessments (fiduciary_id, assessed_at DESC, created_at DESC);

-- Comment the table + key columns for pg_dump / introspection tooling.
COMMENT ON TABLE  om_assessments                 IS 'vAIb-a0a0: per-tenant landing cache of the OM-pushed cross-source DPIA verdict (Direction 1 OM->CMS). One row per OM assessment run; latest by assessed_at is the current cached OM verdict. Value-free / metadata-only — NO principal PII.';
COMMENT ON COLUMN om_assessments.fiduciary_id    IS 'Server-derived tenant scope (from the pushing OM app api-key). One OM domain <-> one fiduciary_id; a push can only write the matching tenant''s row.';
COMMENT ON COLUMN om_assessments.om_domain       IS 'OM Domain FQN the verdict came from (wix-<instanceId>). Traceability metadata only; NOT the authority (fiduciary_id is).';
COMMENT ON COLUMN om_assessments.dpia_status     IS 'Combined worst-wins compliance status: compliant / attention / non_compliant.';
COMMENT ON COLUMN om_assessments.dpia_gaps       IS 'Value-free gap CODES + total (jsonb). NO PII values.';
COMMENT ON COLUMN om_assessments.per_integration IS 'Per-integration roll-up [{service, platform, status, score, activities, gaps}...] — counts/statuses only, NO PII.';
