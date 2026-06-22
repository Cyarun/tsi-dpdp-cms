-- 04_purge_oversight.sql
-- Purge oversight: route erasure/withdrawal to the DPO for confirmation, with a
-- legal-retention exception (litigation hold) that BLOCKS a purge.
-- DPDP Act 2023: Section 8(7) erasure-on-withdrawal obligation, qualified by the
-- Section 8(8) / Section 17 legal-retention exceptions (e.g. litigation hold).
--
-- NOTE: the base purge_requests table is defined in 01_init.sql with the minimal
-- columns (id, user_id, fiduciary_id, purpose_id, app_id, trigger_event, status,
-- initiated_at, details, last_updated_at). This migration adds the oversight
-- columns the DPO-confirm workflow needs. All ADDs are IF NOT EXISTS so this is
-- safe to re-run and safe on an already-populated table.

-- --- DPO confirmation / fulfillment columns on purge_requests -----------------
ALTER TABLE purge_requests
    ADD COLUMN IF NOT EXISTS records_affected_count INTEGER;            -- set at COMPLETED by the DPO
ALTER TABLE purge_requests
    ADD COLUMN IF NOT EXISTS confirmed_by            UUID REFERENCES operators(id); -- the DPO who confirmed (approver, from session)
ALTER TABLE purge_requests
    ADD COLUMN IF NOT EXISTS confirmed_at            TIMESTAMP WITH TIME ZONE;       -- when INITIATED -> CONFIRMED
ALTER TABLE purge_requests
    ADD COLUMN IF NOT EXISTS completed_at            TIMESTAMP WITH TIME ZONE;       -- when CONFIRMED -> COMPLETED
ALTER TABLE purge_requests
    ADD COLUMN IF NOT EXISTS legal_exception_applied_id UUID;           -- FK added after legal_retention_exceptions exists (below)

-- --- Legal retention exceptions (litigation hold) -----------------------------
-- A DPO applies an exception for a principal + a set of data categories to BLOCK
-- a purge. While an exception is ACTIVE, any purge_request for that principal that
-- overlaps the held categories is held at status UNDER_LEGAL_HOLD instead of being
-- confirmed/completed.
CREATE TABLE IF NOT EXISTS legal_retention_exceptions (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fiduciary_id            UUID NOT NULL REFERENCES fiduciaries(id),
    user_id                 VARCHAR(255) NOT NULL,                 -- Data Principal held
    data_categories         JSONB NOT NULL DEFAULT '[]',           -- categories under hold ([] = all categories)
    legal_basis             TEXT NOT NULL,                         -- e.g. 'Litigation hold - Case #1234', statutory ref
    status                  VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
                                CHECK (status IN ('ACTIVE','LIFTED')),
    applied_by              UUID REFERENCES operators(id),         -- DPO who applied the hold (from session)
    applied_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    lifted_by               UUID REFERENCES operators(id),
    lifted_at               TIMESTAMP WITH TIME ZONE,
    expires_at              TIMESTAMP WITH TIME ZONE,              -- optional auto-expiry of the hold
    created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Now that the table exists, wire the FK from purge_requests.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_purge_legal_exception'
    ) THEN
        ALTER TABLE purge_requests
            ADD CONSTRAINT fk_purge_legal_exception
            FOREIGN KEY (legal_exception_applied_id) REFERENCES legal_retention_exceptions(id);
    END IF;
END$$;

-- --- Indexes ------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_purge_requests_confirmed_by   ON purge_requests (confirmed_by);
CREATE INDEX IF NOT EXISTS idx_legal_exceptions_active_user  ON legal_retention_exceptions (fiduciary_id, user_id, status);
CREATE INDEX IF NOT EXISTS idx_legal_exceptions_status       ON legal_retention_exceptions (status, applied_at DESC);
