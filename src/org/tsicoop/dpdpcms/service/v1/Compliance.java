package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*; // Assuming these framework classes are available
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.tsicoop.dpdpcms.util.Constants;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement; // For Statement.RETURN_GENERATED_KEYS
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.Optional;

// Assuming calls to other services like ConsentRecordService and AuditLogService
// import org.tsicoop.dpdpcms.consent.ConsentRecordService; // Example
// import org.tsicoop.dpdpcms.audit.AuditLogService; // Example

/**
 * DataRetentionService class for managing data retention policies and purge operations.
 * All operations are exposed via the POST method, using a '_func' attribute
 * in the JSON request body to specify the desired operation.
 *
 * This class serves as the backend service for the Data Retention Policy Configuration
 * and Data Purge Reports modules of the DPDP Consent Management System.
 *
 * NOTE ON DATABASE SCHEMA ASSUMPTIONS:
 * - Table is named 'retention_policies'.
 * - Columns: id (UUID PK), fiduciary_id (UUID), name (VARCHAR), description (TEXT),
 * applicable_purposes (JSONB), applicable_data_categories (JSONB),
 * retention_duration_value (INTEGER), retention_duration_unit (VARCHAR),
 * retention_start_event (VARCHAR), action_at_expiry (VARCHAR), legal_reference (TEXT),
 * status (VARCHAR), created_at (TIMESTAMPZ), created_by_user_id (UUID),
 * last_updated_at (TIMESTAMPZ), last_updated_by_user_id (UUID).
 * - Table is named 'purge_requests'.
 * - Columns: id (UUID PK), user_id (VARCHAR), fiduciary_id (UUID), processor_id (UUID),
 * trigger_event (VARCHAR), data_categories_to_purge (JSONB), processing_purposes_affected (JSONB),
 * status (VARCHAR), initiated_at (TIMESTAMPZ), completed_at (TIMESTAMPZ),
 * records_affected_count (INTEGER), details (TEXT), legal_exception_applied_id (UUID),
 * error_message (TEXT), confirmed_by_entity_id (UUID), confirmed_at (TIMESTAMPZ),
 * created_by_user_id (UUID), last_updated_at (TIMESTAMPZ).
 * - Assumes 'fiduciaries', 'users', 'legal_retention_exceptions' tables exist for FKs and lookups.
 */
public class Compliance implements Action {

    // --- Canonical purge_request lifecycle (DPO oversight) ---
    // Erasure/withdrawal routes here as INITIATED; the DPO CONFIRMS, then marks COMPLETED.
    // A legal-retention exception parks a request at UNDER_LEGAL_HOLD (purge blocked).
    private static final String STATUS_INITIATED       = "INITIATED";
    private static final String STATUS_CONFIRMED       = "CONFIRMED";
    private static final String STATUS_COMPLETED       = "COMPLETED";
    private static final String STATUS_FAILED          = "FAILED";
    private static final String STATUS_UNDER_LEGAL_HOLD = "UNDER_LEGAL_HOLD";

    /**
     * Handles all Data Retention and Purge Management operations via a single POST endpoint.
     * The specific operation is determined by the '_func' attribute in the JSON request body.
     *
     * @param req The HttpServletRequest containing the JSON input.
     * @param res The HttpServletResponse for sending the JSON output.
     */
    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        JSONObject output = null;
        JSONArray outputArray = null;
        UUID appId = null;
        UUID loginUserId = null;

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");
            // For client APIs
            String apiKey = req.getHeader("X-API-Key");
            String apiSecret = req.getHeader("X-API-Secret");
            // For Admin APIs
            loginUserId = InputProcessor.getAuthenticatedUserId(req);
            // For apps
            appId = new ApiKey().getAppId(apiKey,apiSecret);

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute in input JSON.", req.getRequestURI());
                return;
            }

            UUID fiduciaryId = null;
            String fiduciaryIdStr = input.get("fiduciary_id") != null?(String) input.get("fiduciary_id"):new Fiduciary().getFiduciaryId(UUID.fromString(apiKey),apiSecret);
            // SEC (vAIb-ktvf review #2): the CREDENTIAL-derived fiduciary — NEVER the body. The body
            // fiduciary_id above is a display/listing filter that the caller can pass; it must NOT be
            // trusted as the tenant identity on the deletion/oversight path (a tenant-A api-key could
            // pass body fiduciary_id=tenantB + a guessed UUID to read/FAIL tenant-B's purges). For the
            // client path the tenant IS the api-key's fiduciary; for the admin path it's the operator's.
            UUID credentialFiduciaryId = null;
            try {
                if (apiKey != null) credentialFiduciaryId = UUID.fromString(new Fiduciary().getFiduciaryId(UUID.fromString(apiKey), apiSecret));
            } catch (Exception ignore) { /* admin path has no api-key → resolved from the operator below */ }
            if (fiduciaryIdStr != null && !fiduciaryIdStr.isEmpty()) {
                try {
                    fiduciaryId = UUID.fromString(fiduciaryIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'fiduciary_id' format.", req.getRequestURI());
                    return;
                }
            }

            switch (func.toLowerCase()) {
                // --- Purge Request Management ---
                case "initiate_purge_request": {
                    // Called by the erasure/withdrawal flow (Consent/Wallet client APIs) to route a
                    // purge to the DPO. NOT an auto-purge: the row lands as INITIATED and waits for
                    // a DPO to CONFIRM it. If an ACTIVE legal hold covers this principal+categories,
                    // the request is parked at UNDER_LEGAL_HOLD instead (purge blocked).
                    String userId = (String) input.get("user_id");
                    String triggerEvent = (String) input.get("trigger_event");
                    // purpose_id is NOT NULL in the schema; erasure (all purposes) uses the '*' sentinel.
                    String purposeId = (String) input.get("purpose_id");
                    if (purposeId == null || purposeId.trim().isEmpty()) {
                        purposeId = "*";
                    }
                    UUID purgeAppId = appId; // resolved from API key for client/app calls
                    String appIdStr = (String) input.get("app_id");
                    if (purgeAppId == null && appIdStr != null && !appIdStr.isEmpty()) {
                        try { purgeAppId = UUID.fromString(appIdStr); } catch (IllegalArgumentException e) {
                            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'app_id' format for purge request.", req.getRequestURI());
                            return;
                        }
                    }
                    // vAIb-i9ja (C3 coverage fuse): an ORPHAN_NO_CONSENT subject has NO
                    // linked data processor by definition — it surfaced from the platform
                    // coverage scan, not from any app's consent flow. Force app_id=NULL so
                    // the row reads "No Linked Processor" (mirrors CESService.recordOrphan
                    // ComplianceEvent), regardless of which tenant api-key carried the call.
                    if (Constants.PURGE_TRIGGER_ORPHAN_NO_CONSENT.equals(triggerEvent)) {
                        purgeAppId = null;
                    }

                    // SEC (vAIb-ktvf class / vAIb-i9ja C3): the purge WRITE is tenant-scoped to the
                    // CREDENTIAL-derived fiduciary (operator on admin path / api-key on client path),
                    // NEVER the body fiduciary_id — else a tenant-A api-key could pass body
                    // fiduciary_id=tenantB and create a purge row in tenant-B's DPO queue (cross-tenant
                    // WRITE). The C3 coverage fuse drives this path with the tenant's own api-key, so
                    // the credential fiduciary IS the verified tenant; the body value is ignored here.
                    UUID purgeCallerFid = (loginUserId != null) ? getOperatorFiduciary(loginUserId) : credentialFiduciaryId;
                    if (purgeCallerFid == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Cannot resolve the caller's fiduciary for this operation.", req.getRequestURI());
                        return;
                    }
                    if (userId == null || userId.isEmpty() || triggerEvent == null || triggerEvent.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (user_id, trigger_event) for 'initiate_purge_request'.", req.getRequestURI());
                        return;
                    }

                    String details = (String) input.get("details");
                    output = initiatePurgeRequest(userId, purgeCallerFid, purposeId, purgeAppId, triggerEvent, details, loginUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;
                }

                case "update_purge_status":
                    UUID purgeRequestId = null;
                    String purgeRequestIdStr = (String) input.get("id");
                    if (purgeRequestIdStr != null && !purgeRequestIdStr.isEmpty()) {
                        try { purgeRequestId = UUID.fromString(purgeRequestIdStr); } catch (IllegalArgumentException e) { /* handled below */ }
                    }
                    if (purgeRequestId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'purge_request_id' is required for 'update_purge_status'.", req.getRequestURI());
                        return;
                    }
                    String status = (String) input.get("status"); // CONFIRMED, COMPLETED, FAILED
                    String updDetails = (String) input.get("details");
                    // records_affected_count is the DPO's attested count of rows actually purged (set at COMPLETED).
                    Integer recordsAffected = null;
                    Object rac = input.get("records_affected_count");
                    if (rac instanceof Long) recordsAffected = ((Long) rac).intValue();
                    else if (rac instanceof Number) recordsAffected = ((Number) rac).intValue();

                    // SEC (vAIb-ktvf review): the caller fiduciary MUST be server-derived, not the
                    // trusted body. Admin path → the operator's own fiduciary; client path → the
                    // api-key's fiduciary (already server-derived into fiduciaryId at the top).
                    UUID updCallerFid = (loginUserId != null) ? getOperatorFiduciary(loginUserId) : credentialFiduciaryId;
                    if (updCallerFid == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Cannot resolve the caller's fiduciary for this operation.", req.getRequestURI());
                        return;
                    }
                    JSONObject updResult = updatePurgeStatus(purgeRequestId, status, updDetails, recordsAffected, loginUserId, appId, updCallerFid);
                    if (Boolean.FALSE.equals(updResult.get("success"))) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", (String) updResult.get("message"), req.getRequestURI());
                    } else {
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, updResult);
                    }
                    break;

                case "list_purge_requests":
                    String purgeStatusFilter = (String) input.get("status");
                    String purgeTriggerFilter = (String) input.get("trigger_event");
                    String purgeSearch = (String) input.get("search");
                    // SEC (vAIb-ktvf review #2): list is tenant-scoped to the CREDENTIAL-derived
                    // fiduciary (operator on admin path / api-key on client path), NOT the body —
                    // else a tenant could list another tenant's purges via body fiduciary_id.
                    UUID listCallerFid = (loginUserId != null) ? getOperatorFiduciary(loginUserId) : credentialFiduciaryId;
                    if (listCallerFid == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Cannot resolve the caller's fiduciary for this operation.", req.getRequestURI());
                        return;
                    }
                    int page = (input.get("page") instanceof Long) ? ((Long)input.get("page")).intValue() : 1;
                    int limit = (input.get("limit") instanceof Long) ? ((Long)input.get("limit")).intValue() : 20;

                    outputArray = listPurgeRequestsFromDb(listCallerFid, appId, purgeStatusFilter, purgeTriggerFilter, purgeSearch, page, limit);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;

                case "get_purge_request":
                    String id = (String) input.get("id");
                    // SEC (vAIb-ktvf review): caller fiduciary server-derived (operator on admin
                    // path, api-key on client path), used as the tenant predicate in the query.
                    UUID getCallerFid = (loginUserId != null) ? getOperatorFiduciary(loginUserId) : credentialFiduciaryId;
                    if (getCallerFid == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Cannot resolve the caller's fiduciary for this operation.", req.getRequestURI());
                        return;
                    }
                    output = getPurgeRequestsFromDb(id, getCallerFid);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;

                // --- Legal Retention Exceptions (litigation hold) ---
                case "apply_legal_exception": {
                    // A DPO blocks a purge for a principal + data_categories (e.g. litigation hold).
                    String userId = (String) input.get("user_id");
                    String legalBasis = (String) input.get("legal_basis");
                    JSONArray dataCategories = (JSONArray) input.get("data_categories");
                    // SEC (vAIb-ktvf review #2): legal holds gate deletions cross-tenant → scope to the
                    // CREDENTIAL-derived fiduciary, never the body. Legal holds are DPO actions → require
                    // an admin/DPO session (writer != approver); a bare api-key cannot apply a hold.
                    UUID applyFid = getOperatorFiduciary(loginUserId);
                    if (applyFid == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Applying a legal hold requires an authenticated DPO session.", req.getRequestURI());
                        return;
                    }
                    if (userId == null || userId.isEmpty() || legalBasis == null || legalBasis.trim().isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (user_id, legal_basis) for 'apply_legal_exception'.", req.getRequestURI());
                        return;
                    }
                    output = applyLegalException(applyFid, userId, dataCategories, legalBasis, loginUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;
                }

                case "lift_legal_exception": {
                    UUID exceptionId = null;
                    String exceptionIdStr = (String) input.get("id");
                    if (exceptionIdStr != null && !exceptionIdStr.isEmpty()) {
                        try { exceptionId = UUID.fromString(exceptionIdStr); } catch (IllegalArgumentException e) { /* handled below */ }
                    }
                    if (exceptionId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'id' (exception id) is required for 'lift_legal_exception'.", req.getRequestURI());
                        return;
                    }
                    // SEC: lift = a DPO action that re-enables a deletion → require DPO session +
                    // credential-derived fiduciary (liftLegalException already scopes by fiduciary_id).
                    UUID liftFid = getOperatorFiduciary(loginUserId);
                    if (liftFid == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Lifting a legal hold requires an authenticated DPO session.", req.getRequestURI());
                        return;
                    }
                    output = liftLegalException(exceptionId, liftFid, loginUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;
                }

                case "list_legal_exceptions": {
                    // SEC: tenant-scope to the credential-derived fiduciary (operator/api-key), not body.
                    UUID listLegalFid = (loginUserId != null) ? getOperatorFiduciary(loginUserId) : credentialFiduciaryId;
                    if (listLegalFid == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Cannot resolve the caller's fiduciary for this operation.", req.getRequestURI());
                        return;
                    }
                    String legalUserFilter = (String) input.get("user_id");
                    String legalStatusFilter = (String) input.get("status");
                    outputArray = listLegalExceptions(listLegalFid, legalUserFilter, legalStatusFilter);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;
                }

                case "list_coverage_findings": {
                    // SEC: tenant-scope to the credential-derived fiduciary (operator/api-key), not body.
                    UUID covFid = (loginUserId != null) ? getOperatorFiduciary(loginUserId) : credentialFiduciaryId;
                    if (covFid == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Cannot resolve the caller's fiduciary for this operation.", req.getRequestURI());
                        return;
                    }
                    output = getLatestCoverageFinding(covFid);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    break;
                }

                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown or unsupported '_func' value: " + func, req.getRequestURI());
                    break;
            }
        } catch (SQLException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", "A database error occurred: " + e.getMessage(), req.getRequestURI());
        } catch (ParseException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid JSON input: " + e.getMessage(), req.getRequestURI());
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid UUID or date format in input: " + e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", "An unexpected error occurred: " + e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * Validates the HTTP method and request content type.
     * @param method The HTTP method of the request.
     * @param req The HttpServletRequest.
     * @param res The HttpServletResponse.
     * @return true if validation passes, false otherwise.
     */
    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for Data Retention & Purge Management operations.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res); // This validates content-type and basic body parsing
    }



    /**
     * In-process entry point for the erasure/withdrawal flow to route a purge to the
     * DPO without going back out over HTTP. The Consent/Wallet services call this
     * after recording an erasure so the request lands in the DPO queue as INITIATED
     * (or UNDER_LEGAL_HOLD if a hold is active). Returns the new purge request id, or
     * null on failure — callers MUST treat a null/failed routing as non-fatal so the
     * core erasure flow is never blocked by purge-routing.
     *
     * Wiring (one line, added by the Consent/Wallet owner, out of this lane):
     *   if (erasure) new Compliance().routeErasureToDpo(userId, fiduciaryId, appId, null);
     */
    public String routeErasureToDpo(String userId, UUID fiduciaryId, UUID appId, String details) {
        try {
            JSONObject res = initiatePurgeRequest(userId, fiduciaryId, "*", appId,
                    Constants.PURGE_TRIGGER_ERASURE, details, null);
            if (Boolean.TRUE.equals(res.get("success"))) {
                JSONObject data = (JSONObject) res.get("data");
                return data != null ? (String) data.get("purge_request_id") : null;
            }
        } catch (Exception e) {
            // Non-fatal: erasure provenance is already recorded by the caller; the
            // CES retention sweep will also create a purge request if this missed.
            System.err.println("routeErasureToDpo failed (non-fatal): " + e.getMessage());
        }
        return null;
    }

    /**
     * Initiates a purge request, routing it to the DPO for confirmation.
     * Called by the erasure/withdrawal flow (Consent/Wallet client APIs) and by an
     * internal retention-expiry scheduler. This is NOT an auto-purge: the row is
     * created as INITIATED and waits for a DPO to CONFIRM and COMPLETE it.
     *
     * Legal hold: if an ACTIVE legal_retention_exception covers this principal and
     * (any of) the affected data categories, the request is parked at
     * UNDER_LEGAL_HOLD instead of INITIATED, so the purge is blocked until lifted.
     *
     * @return JSONObject containing the new purge request's ID and routed status.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject initiatePurgeRequest(String userId, UUID fiduciaryId, String purposeId, UUID appId,
                                            String triggerEvent, String details, UUID loginUserId) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        // vAIb-i9ja (C3 coverage fuse): the coverage scan re-runs on every "Run
        // Compliance Check" (nightly + on-demand), so an unactioned orphan would be
        // re-routed every run. IDEMPOTENT for the orphan trigger: if an OPEN
        // (INITIATED / UNDER_LEGAL_HOLD) orphan request already exists for this
        // principal, return it instead of inserting a duplicate. Erasure/expiry keep
        // their existing behaviour (they are already gated by lastCESRun in CESService).
        if (Constants.PURGE_TRIGGER_ORPHAN_NO_CONSENT.equals(triggerEvent)) {
            UUID existing = findOpenPurgeRequestId(fiduciaryId, userId, triggerEvent);
            if (existing != null) {
                output.put("purge_request_id", existing.toString());
                output.put("status", "EXISTING");
                output.put("blocked_by_legal_hold", false);
                output.put("message", "Orphan already routed to DPO; existing open request reused (idempotent).");
                return new JSONObject() {{ put("success", true); put("data", output); }};
            }
        }

        // If a litigation hold already covers this principal, route as UNDER_LEGAL_HOLD (purge blocked).
        UUID activeHoldId = findActiveLegalHoldId(fiduciaryId, userId);
        String initialStatus = (activeHoldId != null) ? STATUS_UNDER_LEGAL_HOLD : STATUS_INITIATED;

        String sql = "INSERT INTO purge_requests (id, user_id, fiduciary_id, purpose_id, app_id, trigger_event, status, details, legal_exception_applied_id, initiated_at, last_updated_at) " +
                "VALUES (uuid_generate_v4(), ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW()) RETURNING id";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            pstmt.setString(1, userId);
            pstmt.setObject(2, fiduciaryId);
            pstmt.setString(3, purposeId);
            pstmt.setObject(4, appId);
            pstmt.setString(5, triggerEvent);
            pstmt.setString(6, initialStatus);
            pstmt.setString(7, details);
            pstmt.setObject(8, activeHoldId);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Initiating purge request failed, no rows affected.");
            }

            rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                String purgeRequestId = rs.getString(1);
                output.put("purge_request_id", purgeRequestId);
                output.put("status", initialStatus);
                output.put("blocked_by_legal_hold", activeHoldId != null);
                output.put("message", activeHoldId != null
                        ? "Purge request created but BLOCKED by an active legal hold; routed to DPO for review."
                        : "Purge request initiated and routed to DPO for confirmation.");
            } else {
                throw new SQLException("Initiating purge request failed, no ID obtained.");
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }

        // Audit: record initiation (and whether it was held) for the DPDP accountability trail.
        String auditAction = (activeHoldId != null) ? Constants.EVENT_LEGAL_HOLD_APPLIED : Constants.EVENT_PURGE_INITIATED;
        new Audit().logEventAsync(userId, fiduciaryId, Constants.SERVICE_TYPE_SYSTEM, appId, auditAction,
                "purge_request:" + output.get("purge_request_id") + " trigger:" + triggerEvent);

        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    /**
     * Transitions a purge request through the DPO oversight lifecycle:
     *   INITIATED -> CONFIRMED -> COMPLETED   (happy path; DPO drives both steps)
     *   INITIATED/CONFIRMED -> FAILED         (manual review needed)
     * The DPO is captured from the session (loginUserId) as confirmed_by — the
     * approver is recorded separately from the system/app that initiated the row
     * (writer != approver, mirroring the RoPA publish gate). records_affected_count
     * is the DPO's attested count, persisted at COMPLETED.
     *
     * Guards:
     *  - A request UNDER_LEGAL_HOLD cannot be confirmed/completed (purge blocked).
     *  - Illegal transitions (e.g. INITIATED -> COMPLETED, or any move out of a
     *    terminal state) are rejected with success=false.
     *
     * @return JSONObject with success flag and message (success=false on a rejected transition).
     * @throws SQLException if a database access error occurs.
     */
    /**
     * SEC (vAIb-ktvf review): resolve an authenticated operator's OWN fiduciary SERVER-SIDE from
     * the operators table — never trust a body fiduciary_id on the deletion path. A platform
     * operator (NULL fiduciary) returns null → the caller must reject (no implicit all-tenant).
     */
    /**
     * Returns the latest coverage_findings row for the given fiduciary, or {found:false} when none.
     * @return JSONObject with coverage stats or {found:false}.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject getLatestCoverageFinding(UUID fiduciaryId) throws SQLException {
        JSONObject out = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        String sql = "SELECT id, scanned_at, baseline_activity_count, covered_count, gap_count, gap_activities " +
                     "FROM coverage_findings WHERE fiduciary_id = ? ORDER BY scanned_at DESC LIMIT 1";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                out.put("found", true);
                out.put("baseline_activity_count", rs.getInt("baseline_activity_count"));
                out.put("covered_count", rs.getInt("covered_count"));
                out.put("gap_count", rs.getInt("gap_count"));
                if (rs.getTimestamp("scanned_at") != null) {
                    out.put("scanned_at", rs.getTimestamp("scanned_at").toInstant().toString());
                }
                // Parse the gap_activities JSONB column (array of activity-name strings).
                String gapRaw = rs.getString("gap_activities");
                JSONArray gapArr = new JSONArray();
                if (gapRaw != null && !gapRaw.isEmpty()) {
                    try {
                        Object parsed = new JSONParser().parse(gapRaw);
                        if (parsed instanceof JSONArray) gapArr = (JSONArray) parsed;
                    } catch (ParseException ignore) { /* return empty array on malformed JSONB */ }
                }
                out.put("gap_activities", gapArr);
            } else {
                out.put("found", false);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return out;
    }

    private UUID getOperatorFiduciary(UUID operatorId) throws SQLException {
        if (operatorId == null) return null;
        PoolDB pool = new PoolDB();
        try (Connection conn = pool.getConnection();
             PreparedStatement ps = conn.prepareStatement("SELECT fiduciary_id FROM operators WHERE id = ? AND status = 'ACTIVE'")) {
            ps.setObject(1, operatorId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    String f = rs.getString("fiduciary_id");
                    return (f != null) ? UUID.fromString(f) : null;
                }
            }
        }
        return null;
    }

    private JSONObject updatePurgeStatus(UUID purgeRequestId, String targetStatus, String details,
                                         Integer recordsAffected, UUID loginUserId, UUID appId,
                                         UUID callerFiduciaryId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String userId = null;
        UUID fiduciaryId = null;
        String currentStatus = null;

        if (targetStatus == null) {
            return new JSONObject() {{ put("success", false); put("message", "Missing target 'status'."); }};
        }
        targetStatus = targetStatus.trim().toUpperCase();

        try {
            conn = pool.getConnection();

            // Read current state first so we can enforce the lifecycle.
            pstmt = conn.prepareStatement("SELECT user_id, fiduciary_id, status FROM purge_requests WHERE id = ?");
            pstmt.setObject(1, purgeRequestId);
            rs = pstmt.executeQuery();
            if (!rs.next()) {
                return new JSONObject() {{ put("success", false); put("message", "Purge request not found."); }};
            }
            userId = rs.getString("user_id");
            fiduciaryId = UUID.fromString(rs.getString("fiduciary_id"));
            currentStatus = rs.getString("status");
            rs.close();
            pstmt.close();

            // SEC (vAIb-ktvf review): TENANT SCOPE on the irreversible deletion path. The
            // row's fiduciary must equal the CALLER's server-derived fiduciary, else a
            // tenant-A operator / any SCOPE_PURGE key could drive another tenant's purge to
            // COMPLETED by guessing its UUID. Fail-closed (404, no oracle) on mismatch/absent.
            if (callerFiduciaryId == null || !callerFiduciaryId.equals(fiduciaryId)) {
                return new JSONObject() {{ put("success", false); put("message", "Purge request not found."); }};
            }

            final String curr = currentStatus == null ? "" : currentStatus.toUpperCase();
            final String tgt = targetStatus;

            // SEC: the data-deleting transitions (CONFIRMED/COMPLETED) require an authenticated
            // DPO/admin session (writer != approver). On the client-API path loginUserId is null
            // → reject, so a non-DPO key cannot finalize an erasure with no recorded approver.
            if ((STATUS_CONFIRMED.equals(tgt) || STATUS_COMPLETED.equals(tgt)) && loginUserId == null) {
                return new JSONObject() {{ put("success", false); put("message", "Confirming or completing a purge requires an authenticated DPO session."); }};
            }

            // Legal hold blocks the purge entirely.
            if (STATUS_UNDER_LEGAL_HOLD.equals(curr)) {
                return new JSONObject() {{ put("success", false); put("message", "Purge is UNDER_LEGAL_HOLD and cannot be confirmed or completed. Lift the legal exception first."); }};
            }
            // Terminal states cannot move.
            if (STATUS_COMPLETED.equals(curr) || STATUS_FAILED.equals(curr)) {
                return new JSONObject() {{ put("success", false); put("message", "Purge request is in a terminal state (" + curr + ") and cannot change."); }};
            }
            // Enforce allowed transitions.
            boolean allowed =
                    (STATUS_INITIATED.equals(curr) && (STATUS_CONFIRMED.equals(tgt) || STATUS_FAILED.equals(tgt)))
                 || (STATUS_CONFIRMED.equals(curr) && (STATUS_COMPLETED.equals(tgt) || STATUS_FAILED.equals(tgt)));
            if (!allowed) {
                return new JSONObject() {{ put("success", false); put("message", "Illegal status transition " + curr + " -> " + tgt + "."); }};
            }

            // Build the UPDATE according to the target, stamping the oversight columns.
            StringBuilder upd = new StringBuilder("UPDATE purge_requests SET status = ?, details = ?, last_updated_at = NOW()");
            List<Object> params = new ArrayList<>();
            params.add(tgt);
            params.add(details);
            if (STATUS_CONFIRMED.equals(tgt)) {
                upd.append(", confirmed_by = ?, confirmed_at = NOW()");
                params.add(loginUserId);
            } else if (STATUS_COMPLETED.equals(tgt)) {
                // Carry confirmed_by forward if not already set; stamp completion + attested count.
                upd.append(", completed_at = NOW(), records_affected_count = ?, confirmed_by = COALESCE(confirmed_by, ?)");
                params.add(recordsAffected);
                params.add(loginUserId);
            }
            upd.append(" WHERE id = ?");
            params.add(purgeRequestId);

            pstmt = conn.prepareStatement(upd.toString());
            for (int i = 0; i < params.size(); i++) pstmt.setObject(i + 1, params.get(i));
            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                return new JSONObject() {{ put("success", false); put("message", "Purge status update failed, no rows affected."); }};
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }

        // Audit (DPO console action: the operator session is the actor).
        String serviceType = (appId != null) ? Constants.SERVICE_TYPE_APP : Constants.SERVICE_TYPE_DPO_CONSOLE;
        String auditAction;
        if (STATUS_CONFIRMED.equals(targetStatus)) auditAction = Constants.EVENT_PURGE_IN_PROGRESS;
        else if (STATUS_COMPLETED.equals(targetStatus)) auditAction = Constants.EVENT_PURGE_COMPLETED;
        else auditAction = Constants.EVENT_PURGE_FAILED;
        String auditCtx = "purge_request:" + purgeRequestId + " " + currentStatus + "->" + targetStatus
                + (recordsAffected != null ? " records:" + recordsAffected : "")
                + (details != null ? " note:" + details : "");
        new Audit().logEventAsync(userId, fiduciaryId, serviceType, loginUserId, auditAction, auditCtx);

        final String ts = targetStatus;
        return new JSONObject() {{
            put("success", true);
            put("status", ts);
            put("message", "Purge status updated to " + ts + ".");
        }};
    }

    /**
     * Returns the id of an ACTIVE legal_retention_exception that covers this principal
     * (and is not past its optional expiry), or null if none. A blanket hold (empty
     * data_categories) covers everything for the principal.
     * @throws SQLException if a database access error occurs.
     */
    /**
     * vAIb-i9ja (C3): returns the id of an OPEN purge_request (INITIATED or
     * UNDER_LEGAL_HOLD — i.e. not yet actioned/terminal) for this principal +
     * trigger, or null if none. Used to make orphan routing IDEMPOTENT across the
     * repeated coverage scans a "Run Compliance Check" fires. Tenant-scoped by
     * fiduciary_id (the caller passes the server-derived fiduciary).
     * @throws SQLException if a database access error occurs.
     */
    private UUID findOpenPurgeRequestId(UUID fiduciaryId, String userId, String triggerEvent) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        UUID id = null;
        String sql = "SELECT id FROM purge_requests " +
                "WHERE fiduciary_id = ? AND user_id = ? AND trigger_event = ? " +
                "AND status IN (?, ?) ORDER BY initiated_at DESC LIMIT 1";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            pstmt.setString(2, userId);
            pstmt.setString(3, triggerEvent);
            pstmt.setString(4, STATUS_INITIATED);
            pstmt.setString(5, STATUS_UNDER_LEGAL_HOLD);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                id = UUID.fromString(rs.getString("id"));
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return id;
    }

    private UUID findActiveLegalHoldId(UUID fiduciaryId, String userId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        UUID holdId = null;
        String sql = "SELECT id FROM legal_retention_exceptions " +
                "WHERE fiduciary_id = ? AND user_id = ? AND status = 'ACTIVE' " +
                "AND (expires_at IS NULL OR expires_at > NOW()) " +
                "ORDER BY applied_at DESC LIMIT 1";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            pstmt.setString(2, userId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                holdId = UUID.fromString(rs.getString("id"));
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return holdId;
    }

    /**
     * Applies a legal-retention exception (e.g. litigation hold) for a principal +
     * data categories. Any OPEN purge request (INITIATED/CONFIRMED) for that principal
     * is parked at UNDER_LEGAL_HOLD so the purge is blocked. The applying DPO is
     * recorded from the session.
     * @return JSONObject with the new exception id.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject applyLegalException(UUID fiduciaryId, String userId, JSONArray dataCategories,
                                          String legalBasis, UUID loginUserId) throws SQLException {
        JSONObject output = new JSONObject();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String exceptionId = null;

        String insSql = "INSERT INTO legal_retention_exceptions (id, fiduciary_id, user_id, data_categories, legal_basis, status, applied_by, applied_at, created_at) " +
                "VALUES (uuid_generate_v4(), ?, ?, ?::jsonb, ?, 'ACTIVE', ?, NOW(), NOW()) RETURNING id";
        // Park any open purge requests for this principal so the purge is blocked.
        String blockSql = "UPDATE purge_requests SET status = ?, legal_exception_applied_id = ?, last_updated_at = NOW() " +
                "WHERE fiduciary_id = ? AND user_id = ? AND status IN (?, ?)";
        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);

            pstmt = conn.prepareStatement(insSql, Statement.RETURN_GENERATED_KEYS);
            pstmt.setObject(1, fiduciaryId);
            pstmt.setString(2, userId);
            pstmt.setString(3, dataCategories != null ? dataCategories.toJSONString() : "[]");
            pstmt.setString(4, legalBasis);
            pstmt.setObject(5, loginUserId);
            pstmt.executeUpdate();
            rs = pstmt.getGeneratedKeys();
            if (rs.next()) exceptionId = rs.getString(1);
            else throw new SQLException("Applying legal exception failed, no ID obtained.");
            rs.close();
            pstmt.close();

            pstmt = conn.prepareStatement(blockSql);
            pstmt.setString(1, STATUS_UNDER_LEGAL_HOLD);
            pstmt.setObject(2, UUID.fromString(exceptionId));
            pstmt.setObject(3, fiduciaryId);
            pstmt.setString(4, userId);
            pstmt.setString(5, STATUS_INITIATED);
            pstmt.setString(6, STATUS_CONFIRMED);
            int blocked = pstmt.executeUpdate();

            conn.commit();
            output.put("exception_id", exceptionId);
            output.put("purge_requests_blocked", blocked);
            output.put("message", "Legal retention exception applied; " + blocked + " open purge request(s) placed UNDER_LEGAL_HOLD.");
        } catch (SQLException e) {
            if (conn != null) conn.rollback();
            throw e;
        } finally {
            if (conn != null) conn.setAutoCommit(true);
            pool.cleanup(rs, pstmt, conn);
        }

        new Audit().logEventAsync(userId, fiduciaryId, Constants.SERVICE_TYPE_DPO_CONSOLE, loginUserId,
                Constants.EVENT_LEGAL_HOLD_APPLIED, "legal_exception:" + exceptionId + " basis:" + legalBasis);

        return new JSONObject() {{ put("success", true); put("data", output); }};
    }

    /**
     * Lifts an ACTIVE legal-retention exception. Purge requests that were parked
     * under THIS exception are released back to INITIATED so the DPO can resume.
     * @return JSONObject success flag.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject liftLegalException(UUID exceptionId, UUID fiduciaryId, UUID loginUserId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String userId = null;
        boolean lifted = false;
        int released = 0;

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);

            // Lift only if currently ACTIVE (and, when provided, scoped to the fiduciary).
            String liftSql = "UPDATE legal_retention_exceptions SET status = 'LIFTED', lifted_by = ?, lifted_at = NOW() " +
                    "WHERE id = ? AND status = 'ACTIVE'" + (fiduciaryId != null ? " AND fiduciary_id = ?" : "") +
                    " RETURNING user_id";
            pstmt = conn.prepareStatement(liftSql);
            pstmt.setObject(1, loginUserId);
            pstmt.setObject(2, exceptionId);
            if (fiduciaryId != null) pstmt.setObject(3, fiduciaryId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                userId = rs.getString("user_id");
                lifted = true;
            }
            rs.close();
            pstmt.close();

            if (!lifted) {
                conn.rollback();
                return new JSONObject() {{ put("success", false); put("message", "Legal exception not found or already lifted."); }};
            }

            // Release purge requests held under this exception back to INITIATED.
            String releaseSql = "UPDATE purge_requests SET status = ?, legal_exception_applied_id = NULL, last_updated_at = NOW() " +
                    "WHERE legal_exception_applied_id = ? AND status = ?";
            pstmt = conn.prepareStatement(releaseSql);
            pstmt.setString(1, STATUS_INITIATED);
            pstmt.setObject(2, exceptionId);
            pstmt.setString(3, STATUS_UNDER_LEGAL_HOLD);
            released = pstmt.executeUpdate();

            conn.commit();
        } catch (SQLException e) {
            if (conn != null) conn.rollback();
            throw e;
        } finally {
            if (conn != null) conn.setAutoCommit(true);
            pool.cleanup(rs, pstmt, conn);
        }

        new Audit().logEventAsync(userId, fiduciaryId, Constants.SERVICE_TYPE_DPO_CONSOLE, loginUserId,
                Constants.EVENT_PURGE_IN_PROGRESS, "legal_exception_lifted:" + exceptionId + " released:" + released);

        final int rel = released;
        return new JSONObject() {{
            put("success", true);
            put("purge_requests_released", rel);
            put("message", "Legal exception lifted; " + rel + " purge request(s) released to INITIATED.");
        }};
    }

    /**
     * Lists legal-retention exceptions for a fiduciary, optionally filtered by
     * principal (user_id) and status.
     * @return JSONArray of exception JSONObjects.
     * @throws SQLException if a database access error occurs.
     */
    private JSONArray listLegalExceptions(UUID fiduciaryId, String userFilter, String statusFilter) throws SQLException {
        JSONArray arr = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sql = new StringBuilder("SELECT id, user_id, data_categories, legal_basis, status, applied_by, applied_at, lifted_by, lifted_at, expires_at FROM legal_retention_exceptions WHERE fiduciary_id = ?");
        List<Object> params = new ArrayList<>();
        params.add(fiduciaryId);
        if (userFilter != null && !userFilter.isEmpty()) {
            sql.append(" AND user_id = ?");
            params.add(userFilter);
        }
        if (statusFilter != null && !statusFilter.isEmpty()) {
            sql.append(" AND status = ?");
            params.add(statusFilter.toUpperCase());
        }
        sql.append(" ORDER BY applied_at DESC");

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql.toString());
            for (int i = 0; i < params.size(); i++) pstmt.setObject(i + 1, params.get(i));
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject ex = new JSONObject();
                ex.put("id", rs.getString("id"));
                ex.put("user_id", rs.getString("user_id"));
                ex.put("data_categories", rs.getString("data_categories"));
                ex.put("legal_basis", rs.getString("legal_basis"));
                ex.put("status", rs.getString("status"));
                ex.put("applied_by", rs.getString("applied_by"));
                if (rs.getTimestamp("applied_at") != null) ex.put("applied_at", rs.getTimestamp("applied_at").toInstant().toString());
                ex.put("lifted_by", rs.getString("lifted_by"));
                if (rs.getTimestamp("lifted_at") != null) ex.put("lifted_at", rs.getTimestamp("lifted_at").toInstant().toString());
                if (rs.getTimestamp("expires_at") != null) ex.put("expires_at", rs.getTimestamp("expires_at").toInstant().toString());
                arr.add(ex);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return arr;
    }

    /**
     * Retrieves a list of purge requests from the database with optional filtering and pagination.
     * @return JSONArray of purge request JSONObjects.
     * @throws SQLException if a database access error occurs.
     */
    private JSONArray listPurgeRequestsFromDb(UUID fiduciaryId, UUID appId, String statusFilter, String triggerFilter, String search, int page, int limit) throws SQLException {
        JSONArray requestsArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        StringBuilder sqlBuilder = new StringBuilder("SELECT pr.id, pr.user_id, pr.purpose_id, pr.fiduciary_id, pr.app_id, pr.trigger_event, pr.status, pr.initiated_at, pr.details, pr.records_affected_count, pr.confirmed_by, pr.confirmed_at, pr.completed_at, pr.legal_exception_applied_id, a.name FROM purge_requests pr LEFT JOIN apps a ON pr.app_id = a.id WHERE pr.fiduciary_id = ?");
        List<Object> params = new ArrayList<>();
        params.add(fiduciaryId);

        if (statusFilter != null && !statusFilter.isEmpty()) {
            sqlBuilder.append(" AND pr.status = ?");
            params.add(statusFilter);
        }
        if (appId != null) {
            sqlBuilder.append(" AND pr.app_id = ?");
            params.add(appId);
        }
        if (triggerFilter != null && !triggerFilter.isEmpty()) {
            sqlBuilder.append(" AND pr.trigger_event = ?");
            params.add(triggerFilter);
        }
        if (search != null && !search.isEmpty()) {
            sqlBuilder.append(" AND (pr.user_id ILIKE ? OR pr.details ILIKE ?)");
            params.add("%" + search + "%");
            params.add("%" + search + "%");
        }

        sqlBuilder.append(" ORDER BY initiated_at DESC LIMIT ? OFFSET ?");
        params.add(limit);
        params.add((page - 1) * limit);

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject request = new JSONObject();
                request.put("id", rs.getString("id"));
                request.put("user_id", rs.getString("user_id"));
                request.put("purpose_id", rs.getString("purpose_id"));
                request.put("fiduciary_id", rs.getString("fiduciary_id"));
                request.put("app_id", rs.getString("app_id"));
                request.put("app_name", rs.getString("name"));
                request.put("trigger_event", rs.getString("trigger_event"));
                request.put("status", rs.getString("status"));
                request.put("initiated_at", rs.getTimestamp("initiated_at").toInstant().toString());
                request.put("details", rs.getString("details"));
                Object rac = rs.getObject("records_affected_count");
                if (rac != null) request.put("records_affected_count", ((Number) rac).intValue());
                request.put("confirmed_by", rs.getString("confirmed_by"));
                if (rs.getTimestamp("confirmed_at") != null) request.put("confirmed_at", rs.getTimestamp("confirmed_at").toInstant().toString());
                if (rs.getTimestamp("completed_at") != null) request.put("completed_at", rs.getTimestamp("completed_at").toInstant().toString());
                request.put("legal_exception_applied_id", rs.getString("legal_exception_applied_id"));
                requestsArray.add(request);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return requestsArray;
    }

    /**
     * Retrieves a list of purge requests from the database with optional filtering and pagination.
     * @return JSONArray of purge request JSONObjects.
     * @throws SQLException if a database access error occurs.
     */
    private JSONObject getPurgeRequestsFromDb(String id, UUID callerFiduciaryId) throws SQLException {
        JSONObject purgeob = null;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        // SEC (vAIb-ktvf review): TENANT SCOPE — a by-id read must be bounded to the caller's
        // fiduciary, else a tenant could read another tenant's purge (incl. principal user_id)
        // by guessing the UUID. AND fiduciary_id = ? on the server-derived caller fiduciary.
        String sql = "SELECT pr.id, pr.user_id, pr.fiduciary_id, pr.purpose_id, pr.app_id, pr.trigger_event, pr.status, pr.initiated_at, pr.details, pr.records_affected_count, pr.confirmed_by, pr.confirmed_at, pr.completed_at, pr.legal_exception_applied_id, a.name FROM purge_requests pr LEFT JOIN apps a ON pr.app_id = a.id WHERE pr.id=? AND pr.fiduciary_id=?";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, UUID.fromString(id));
            pstmt.setObject(2, callerFiduciaryId);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                purgeob = new JSONObject();
                purgeob.put("id", rs.getString("id"));
                purgeob.put("user_id", rs.getString("user_id"));
                purgeob.put("fiduciary_id", rs.getString("fiduciary_id"));
                purgeob.put("purpose_id", rs.getString("purpose_id"));
                purgeob.put("app_id", rs.getString("app_id"));
                purgeob.put("app_name", rs.getString("name"));
                purgeob.put("trigger_event", rs.getString("trigger_event"));
                purgeob.put("status", rs.getString("status"));
                purgeob.put("initiated_at", rs.getTimestamp("initiated_at").toInstant().toString());
                purgeob.put("details", rs.getString("details"));
                Object rac = rs.getObject("records_affected_count");
                if (rac != null) purgeob.put("records_affected_count", ((Number) rac).intValue());
                purgeob.put("confirmed_by", rs.getString("confirmed_by"));
                if (rs.getTimestamp("confirmed_at") != null) purgeob.put("confirmed_at", rs.getTimestamp("confirmed_at").toInstant().toString());
                if (rs.getTimestamp("completed_at") != null) purgeob.put("completed_at", rs.getTimestamp("completed_at").toInstant().toString());
                purgeob.put("legal_exception_applied_id", rs.getString("legal_exception_applied_id"));
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return purgeob;
    }
}