-- 07_discovery_baseline.sql
-- vAIb (RoPA-coverage-baseline U3) — Persist the onboarding discovery footprint as a
-- tenant baseline so RoPA + Compliance can later reconcile actual coverage against it.
--
-- WHY: during wizard onboarding the fabric scans the tenant's data landscape
-- (native fields, apps, forms, collections) and produces a NormalizedInventory.
-- Without persisting that snapshot the CMS has no authoritative baseline to
-- answer "is this RoPA entry still covered?" or "how many activities were
-- declared at onboarding vs. today?". This table is the single source of truth
-- for the INITIAL footprint. NO PII is ever stored — only category/source/
-- activity metadata and counts (the value-free NormalizedInventory shape).
-- Multiple rows per tenant are intentional: the latest by captured_at wins on
-- read; older rows form an audit trail of successive re-scans.
--
-- WHAT this records: one row per capture event, stamping the inventory shape,
-- a total activity_count, and a coarse source_breakdown (e.g. how many
-- activities came from native fields vs. apps vs. forms vs. collections).

-- --- Discovery baseline footprint (per-tenant, append-only) -------------------
CREATE TABLE IF NOT EXISTS discovery_baseline (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fiduciary_id     UUID NOT NULL REFERENCES fiduciaries(id),
    -- When this snapshot was taken. The latest row per fiduciary (ORDER BY
    -- captured_at DESC LIMIT 1) is the current baseline.
    captured_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    -- The value-free NormalizedInventory: sources / collections / apps /
    -- activities — category and structural metadata ONLY, zero PII values.
    inventory        JSONB NOT NULL,
    -- Total number of data-processing activities declared in this capture.
    activity_count   INTEGER NOT NULL DEFAULT 0,
    -- Coarse breakdown by discovery source, e.g.
    -- {"native": 7, "apps": 4, "forms": 2, "collections": 3}.
    -- NULL when not supplied by the caller (older wizard versions).
    source_breakdown JSONB
);

-- Fast lookup: latest baseline for a given fiduciary, or full history in order.
CREATE INDEX IF NOT EXISTS idx_discovery_baseline_fid_captured
    ON discovery_baseline (fiduciary_id, captured_at DESC);
