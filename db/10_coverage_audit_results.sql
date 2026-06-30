-- 10_coverage_audit_results.sql
-- vAIb (mydata-ui stale-countersign) — Persist the owner Coverage Audit result so the
-- DPDPA.center page can show the LAST result instantly instead of re-running a full
-- live Wix scan on every page load.
--
-- WHY: The Coverage Audit (source → covered / derived / orphan breakdown) is expensive
-- to compute — it requires a live Wix API scan across all data sources. Caching the
-- most-recent result in the CMS means the My-Data UI can render immediately on load,
-- and only trigger a fresh scan when the operator explicitly requests one. This table
-- is the single source of truth for the LAST audit result per tenant.
-- Multiple rows per tenant are intentional: the latest by scanned_at wins on read;
-- older rows form an audit trail of successive re-scans.
--
-- WHAT this records: one row per audit event, stamping a PII-FREE coverage summary
-- (per-source covered/derived/orphan counts + totals). NO email addresses, contact
-- values, or personal data are ever stored — only aggregate integer counts.
-- fiduciary_id is ALWAYS server-derived (resolveTenantScope); the body value is
-- never trusted.

-- --- Coverage audit results (per-tenant, append-only) ---------------------------
CREATE TABLE IF NOT EXISTS coverage_audit_results (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fiduciary_id     UUID NOT NULL REFERENCES fiduciaries(id),
    -- When this audit was performed. The latest row per fiduciary (ORDER BY
    -- scanned_at DESC LIMIT 1) is the current cached result.
    scanned_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- The value-free coverage summary: per-source covered/derived/orphan counts
    -- and any additional structural metadata. ZERO PII values — counts only.
    -- E.g. {"wix_contacts": {"covered": 3, "derived": 1, "orphan": 0}, ...}
    summary          JSONB NOT NULL,
    -- Platform-wide totals rolled up from all sources in this audit.
    covered_total    INTEGER NOT NULL DEFAULT 0,
    derived_total    INTEGER NOT NULL DEFAULT 0,
    orphan_total     INTEGER NOT NULL DEFAULT 0
);

-- Fast lookup: latest audit result for a given fiduciary, or full history in order.
CREATE INDEX IF NOT EXISTS idx_coverage_audit_results_fid_scanned
    ON coverage_audit_results (fiduciary_id, scanned_at DESC);

-- Comment the table and key columns for pg_dump / introspection tooling.
COMMENT ON TABLE  coverage_audit_results              IS 'Per-tenant cache of Coverage Audit results (vAIb mydata-ui). One row per scan event; latest by scanned_at is the current cached result.';
COMMENT ON COLUMN coverage_audit_results.summary      IS 'Value-free coverage counts only (covered/derived/orphan per source). NO PII values, email addresses, or personal data.';
COMMENT ON COLUMN coverage_audit_results.covered_total IS 'Total data points confirmed covered across all sources in this audit.';
COMMENT ON COLUMN coverage_audit_results.derived_total IS 'Total data points derived (inferred coverage) across all sources in this audit.';
COMMENT ON COLUMN coverage_audit_results.orphan_total  IS 'Total data points with no coverage mapping across all sources in this audit.';
