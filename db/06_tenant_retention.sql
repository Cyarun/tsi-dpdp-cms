-- 06_tenant_retention.sql
-- vAIb-8eem — DATA-SUBJECT retention floor on controller reset / decommission / uninstall.
--
-- WHY (DPDP, NOT a re-onboarding convenience): when a Data Fiduciary (controller) is
-- reset / decommissioned / has the app uninstalled, the data principals' consent
-- records + RoPA + policy MUST be RETAINED for AT LEAST 15 days so their rights
-- (access, withdrawal, grievance, erasure-confirmation) survive the controller's
-- departure. This is a DATA-SUBJECT obligation, independent of whether the controller
-- ever re-onboards. DPDP Act 2023: Section 6 (consent records), Section 8 (accountability
-- + erasure-on-withdrawal — which is qualified, so the principal's record cannot simply
-- vanish when a controller leaves), Section 11/13 (principal rights of access/grievance).
--
-- WHAT this records: ONE durable HOLD row per decommission event, stamping the
-- authoritative ``retain_until``. This is the single source of truth for "this tenant's
-- archived data must survive until X" and the GATE any FUTURE purge job MUST honour.
--
-- IMPORTANT (current state): the CMS has ZERO hard-delete paths today — every "delete"
-- (delete_policy, retire_entry) is a soft status flip (status->ARCHIVED / ->retired),
-- and the CES/JobManager only INSERTs DPO-routed purge_requests; nothing time-deletes a
-- reset tenant's archived consents/RoPA/policy. So the 15-day floor is satisfied
-- TRIVIALLY today. This table makes the floor EXPLICIT + ENFORCEABLE: any future
-- decommission purge (e.g. Wix AppRemoved -> reset + purge after the window) MUST check
-- ``retain_until > now()`` here and REFUSE to hard-delete before it.

-- --- Tenant retention holds (decommission log) --------------------------------
CREATE TABLE IF NOT EXISTS tenant_retention_holds (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fiduciary_id    UUID NOT NULL REFERENCES fiduciaries(id),
    -- The earliest instant any future purge of this tenant's archived data is permitted.
    -- Stamped as max(now() + floor_days, the policy's OWN retention) — NEVER shorter than
    -- the floor. A purge job MUST treat retain_until as a hard wall.
    retain_until    TIMESTAMP WITH TIME ZONE NOT NULL,
    -- The data-subject-rights floor in days (audit of the rule applied at stamp time).
    floor_days      INTEGER NOT NULL DEFAULT 15,
    -- What triggered the decommission (e.g. 'reset_onboarding', 'app_removed'). Operator/
    -- tenant free text is HTML-escaped at the storage boundary (no raw markup persisted).
    trigger_event   VARCHAR(64) NOT NULL DEFAULT 'reset_onboarding',
    reason          TEXT,
    status          VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
                        CHECK (status IN ('ACTIVE','RELEASED')),  -- RELEASED only after retain_until passes + a lawful purge
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Look up the active hold (and the latest retain_until) for a fiduciary fast.
CREATE INDEX IF NOT EXISTS idx_tenant_retention_holds_fid_status
    ON tenant_retention_holds (fiduciary_id, status, retain_until DESC);
