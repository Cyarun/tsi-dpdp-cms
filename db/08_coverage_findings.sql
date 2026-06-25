-- 08_coverage_findings.sql
-- vAIb (RoPA-coverage-baseline U5) — Persist per-tenant CES coverage-reconcile results so
-- the DPO console (U6) can read the gap state without re-querying the baseline each time.
--
-- WHY: the CES job (JobManager.enforce) now runs a single coverage-reconcile pass per scan
-- after the principal loop completes. It compares the onboarding discovery baseline
-- (discovery_baseline.inventory.purposes[].name) against the active RoPA
-- (ropa_entries where status='active') and flags activities that have NO active RoPA entry
-- as COVERAGE GAPS. This table is the durable result of that comparison.
-- Append-only (mirrors discovery_baseline): the latest row per fiduciary by scanned_at is
-- the current coverage state; older rows form an audit trail of successive scans.
-- NO PII is ever stored — only activity names (value-free metadata) and counts.

-- --- Coverage-reconcile findings (per-tenant, append-only) --------------------------
CREATE TABLE IF NOT EXISTS coverage_findings (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fiduciary_id            UUID NOT NULL REFERENCES fiduciaries(id),
    -- When the coverage reconcile ran. The latest row per fiduciary (ORDER BY
    -- scanned_at DESC LIMIT 1) is the current coverage state.
    scanned_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    -- Total number of activities in the baseline (inventory.purposes length).
    baseline_activity_count INTEGER NOT NULL DEFAULT 0,
    -- Baseline activities that HAVE a matching active RoPA entry.
    covered_count           INTEGER NOT NULL DEFAULT 0,
    -- Baseline activities that have NO matching active RoPA entry (the gap).
    gap_count               INTEGER NOT NULL DEFAULT 0,
    -- The list of activity NAMES that are gaps, as a JSON array of strings.
    -- Metadata only — NO PII values, only the activity-name strings from the baseline.
    gap_activities          JSONB
);

-- Fast lookup: latest coverage state for a given fiduciary, or full scan history.
CREATE INDEX IF NOT EXISTS idx_coverage_findings_fid_scanned
    ON coverage_findings (fiduciary_id, scanned_at DESC);
