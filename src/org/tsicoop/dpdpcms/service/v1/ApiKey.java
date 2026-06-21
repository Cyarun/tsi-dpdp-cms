package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.Action;
import org.tsicoop.dpdpcms.framework.PasswordHasher;
import org.tsicoop.dpdpcms.framework.PoolDB;
import org.tsicoop.dpdpcms.framework.InputProcessor;
import org.tsicoop.dpdpcms.framework.OutputProcessor;
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
import java.sql.Statement;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * API Key Management Service (ApiKey).
 * This service manages the secure generation, storage, usage tracking, and lifecycle
 * of API keys for Apps.
 */
public class ApiKey implements Action {

    private static final UUID ADMIN_FID_UUID = UUID.fromString("00000000-0000-0000-0000-000000000000");

    // Thread-safe in-memory cache for API key to App ID mapping
    private static final Map<String, UUID> appCache = new ConcurrentHashMap<>();

    /**
     * Handles all API Key Management operations via a single POST endpoint.
     */
    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        JSONObject output = null;
        JSONArray outputArray = null;

        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required '_func' attribute in input JSON.", req.getRequestURI());
                return;
            }

            // --- Extract common parameters ---
            UUID keyId = null;
            String keyIdStr = (String) input.get("key_id");
            if (keyIdStr != null && !keyIdStr.isEmpty()) {
                try {
                    keyId = UUID.fromString(keyIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'key_id' format.", req.getRequestURI());
                    return;
                }
            }

            UUID fiduciaryId = null;
            String fiduciaryIdStr = (String) input.get("fiduciary_id");
            if (fiduciaryIdStr != null && !fiduciaryIdStr.isEmpty()) {
                try {
                    fiduciaryId = UUID.fromString(fiduciaryIdStr);
                } catch (IllegalArgumentException e) {
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'fiduciary_id' format.", req.getRequestURI());
                    return;
                }
            }

            // Get the ID of the Admin performing the action
            UUID loginUserId = InputProcessor.getAuthenticatedUserId(req);

            // vAIb-ae11: tenant scope is derived from the VERIFIED fiduciary, not the JWT role.
            // The auto-created Wix-owner is role=ADMIN but bound to a CONCRETE tenant, so it must
            // NOT be treated as a cross-tenant platform admin. A tenant-scoped operator is hard-
            // scoped to their own fiduciary; only the PLATFORM admin (null fiduciary) may target a
            // tenant via the body fiduciary_id.
            String callerRole = InputProcessor.getVerifiedRole(req);

            switch (func.toLowerCase()) {
                case "generate_api_key": {
                    // Provisioning: scope must be the caller's own tenant (or, for platform admin,
                    // the named target tenant in the body).
                    UUID genFid = InputProcessor.resolveTenantScope(req, res, true);
                    if (genFid == null) return;
                    fiduciaryId = genFid;
                    String description = (String) input.get("description");
                    JSONArray permissionsJson = (JSONArray) input.get("permissions");
                    String appIdStr = (String) input.get("app_id");

                    UUID appId = null;
                    if (appIdStr != null && !appIdStr.isEmpty()) {
                        try {
                            appId = UUID.fromString(appIdStr);
                        } catch (IllegalArgumentException e) {
                            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid 'processor_id' format.", req.getRequestURI());
                            return;
                        }
                    }

                    if (permissionsJson == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing required fields (permissions) for key generation.", req.getRequestURI());
                        return;
                    }

                    // NOTE: Fiduciary existence check is recommended here but omitted for brevity.

                    output = generateAndSaveApiKey(fiduciaryId, appId, description, permissionsJson, loginUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_CREATED, output);
                    break;
                }

                case "get_api_key_details":
                    if (keyId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'key_id' is required.", req.getRequestURI());
                        return;
                    }
                    // vAIb-ae11: scope the by-id read to the SERVER-DERIVED tenant. A tenant
                    // operator is hard-scoped to their own fiduciary; only a PLATFORM admin may
                    // name the target tenant via the body (403 if absent/invalid).
                    UUID getFid = InputProcessor.resolveTenantScope(req, res, true);
                    if (getFid == null) return;
                    Optional<JSONObject> keyOptional = getApiKeyDetailsFromDb(keyId, getFid);
                    if (keyOptional.isPresent()) {
                        output = keyOptional.get();
                        OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
                    } else {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "API Key with ID '" + keyId + "' not found.", req.getRequestURI());
                    }
                    break;

                case "list_api_keys": {
                    String statusFilter = (String) input.get("status");
                    String search = (String) input.get("search");

                    // vAIb-ae11: scope to the SERVER-DERIVED tenant. A tenant operator only ever
                    // sees their own keys; a PLATFORM admin with no body target sees all tenants'.
                    UUID listScope = InputProcessor.resolveTenantScope(req, res, false);
                    if (listScope == null) return;
                    String listFid = InputProcessor.PLATFORM_ADMIN_FID.equals(listScope) ? null : listScope.toString();
                    outputArray = listApiKeysFromDb(listFid, statusFilter, search);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, outputArray);
                    break;
                }

                case "revoke_api_key": { // Deactivates key instantly
                    if (keyId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'key_id' is required for revocation.", req.getRequestURI());
                        return;
                    }
                    // vAIb-ae11: scope to the SERVER-DERIVED tenant (hard-scoped for tenant
                    // operators; platform admin names the target). Always scoped.
                    UUID revokeFid = InputProcessor.resolveTenantScope(req, res, true);
                    if (revokeFid == null) return;
                    revokeApiKeyInDb(keyId, loginUserId, revokeFid);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, new JSONObject() {{ put("success", true); put("message", "API Key revoked successfully."); }});
                    break;
                }

                case "update_api_key_status": {
                    if (keyId == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'key_id' is required.", req.getRequestURI());
                        return;
                    }
                    // F4: require DB-verified ADMIN role (not the JWT claim) to change key status.
                    if (!"ADMIN".equalsIgnoreCase(callerRole)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "ADMIN role required to change API key status.", req.getRequestURI());
                        return;
                    }
                    // vAIb-ae11: scope to the SERVER-DERIVED tenant (hard-scoped for tenant
                    // operators; platform admin names the target). Replaces the trusted body fid.
                    UUID statusFid = InputProcessor.resolveTenantScope(req, res, true);
                    if (statusFid == null) return;
                    String statusFilter = (String) input.get("status"); // Expected status: ACTIVE, INACTIVE, EXPIRED
                    if (statusFilter == null || statusFilter.isEmpty()) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'status' is required for updating key status.", req.getRequestURI());
                        return;
                    }
                    // Revoke is handled by a separate function (case "revoke_api_key")
                    if (statusFilter.equalsIgnoreCase("REVOKED")) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Use 'revoke_api_key' function to permanently revoke keys.", req.getRequestURI());
                        return;
                    }
                    // F4: only permit a closed set of statuses (defense in depth; reactivation is blocked in the helper).
                    if (!statusFilter.equalsIgnoreCase("ACTIVE") && !statusFilter.equalsIgnoreCase("INACTIVE") && !statusFilter.equalsIgnoreCase("EXPIRED")) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unsupported status value.", req.getRequestURI());
                        return;
                    }
                    updateApiKeyStatusInDb(keyId, statusFilter, statusFid, loginUserId);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, new JSONObject() {{ put("success", true); put("message", "API Key status updated successfully."); }});
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

    // --- Validation and Helper Methods ---

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST method is supported for API Key Management operations.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res);
    }

    /**
     * MOCK: Generates a cryptographically strong API key string.
     */
    private String generateRawApiKey() {
        return UUID.randomUUID().toString() + UUID.randomUUID().toString().replace("-", "");
    }

    private String hashApiKey(String rawKey) {
        return new PasswordHasher().hashPassword(rawKey);
    }

    /**
     * Generates a new API key, saves the hashed value, and returns the raw key.
     */
    private JSONObject generateAndSaveApiKey(UUID fiduciaryId, UUID appId, String description,
                                             JSONArray permissionsJson, UUID loginUserId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        // 1. Generate Raw Key and Hash
        String rawKey = generateRawApiKey();
        String hashedKey = hashApiKey(rawKey);
        String permissionsString = permissionsJson != null ? permissionsJson.toJSONString() : "[]";

        JSONObject output = new JSONObject();
        boolean success = false;

        String sql = "INSERT INTO api_keys (id, key_value, fiduciary_id, app_id, description, permissions, created_at, status) VALUES (uuid_generate_v4(), ?, ?, ?, ?, ?::jsonb, NOW(), 'ACTIVE') RETURNING id";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);

            // NOTE: Storing the HASHED key in the key_value column.
            pstmt.setString(1, hashedKey);
            pstmt.setObject(2, fiduciaryId);
            pstmt.setObject(3, appId);
            pstmt.setString(4, description);
            pstmt.setString(5, permissionsString);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                throw new SQLException("Key generation failed, no rows affected.");
            }

            rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                output.put("key_id", rs.getString(1));
                output.put("raw_api_key", rawKey); // RETURN RAW KEY ONLY ONCE!
                output.put("permissions", permissionsJson);
                output.put("fiduciary_id", fiduciaryId.toString());
                output.put("app_id", appId.toString());

                // NOTE: Audit log service call would go here to log key creation.
            } else {
                throw new SQLException("Key generation failed, no ID obtained.");
            }
            success = true;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        if (success) {
            new  Audit().logEventAsync("ADMIN", ADMIN_FID_UUID, Constants.SERVICE_TYPE_ADMIN_CONSOLE, loginUserId, "GENERATE_API_KEY", "ID:"+appId);
        }
        return new JSONObject() {{ put("success", true); put("data", output); put("message", "API Key created successfully. STORE THIS KEY SAFELY, IT WILL NOT BE SHOWN AGAIN."); }};
    }

    /**
     * Retrieves API key details from the database by its ID. (Does NOT retrieve raw key).
     */
    private Optional<JSONObject> getApiKeyDetailsFromDb(UUID keyId, UUID effectiveFid) throws SQLException {
        return getApiKeyDetailsFromDb(keyId, effectiveFid, false);
    }

    // Unscoped internal lookup retained ONLY for updateApiKeyStatusInDb, which performs its own
    // explicit cross-tenant ownership check (keyFiduciaryId vs body fiduciary_id) before mutating.
    // Not reachable from any tenant-facing by-id read path.
    private Optional<JSONObject> getApiKeyDetailsFromDbUnscoped(UUID keyId) throws SQLException {
        return getApiKeyDetailsFromDb(keyId, null, true);
    }

    private Optional<JSONObject> getApiKeyDetailsFromDb(UUID keyId, UUID effectiveFid, boolean unscoped) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        // Exclude the sensitive key_value hash from being pulled into general objects.
        // Hardening: the tenant predicate is applied unconditionally for caller-facing reads
        // (effectiveFid). Only the explicit internal `unscoped` path (status update, which does
        // its own ownership check) omits it.
        String sql = "SELECT id, fiduciary_id, app_id, description, status, permissions, created_at, expires_at, last_used_at FROM api_keys WHERE id = ?";
        if (!unscoped) {
            sql += " AND fiduciary_id = ?";
        }
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, keyId);
            if (!unscoped) {
                pstmt.setObject(2, effectiveFid);
            }
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject key = new JSONObject();
                key.put("key_id", rs.getString("id"));
                key.put("fiduciary_id", rs.getString("fiduciary_id"));
                key.put("app_id", rs.getString("app_id"));
                key.put("description", rs.getString("description"));
                key.put("status", rs.getString("status"));
                key.put("permissions", new JSONParser().parse(rs.getString("permissions")));
                key.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                key.put("expires_at", rs.getTimestamp("expires_at") != null ? rs.getTimestamp("expires_at").toInstant().toString() : null);
                key.put("last_used_at", rs.getTimestamp("last_used_at") != null ? rs.getTimestamp("last_used_at").toInstant().toString() : null);
                return Optional.of(key);
            }
        } catch (ParseException e) {
            throw new SQLException("Failed to parse JSONB content from DB for API key: " + e.getMessage(), e);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return Optional.empty();
    }

    /**
     * Resolves an API Key and Secret to the corresponding Application UUID.
     * Uses an internal cache to avoid hitting the database for every request validation.
     *
     * @param apiKey The UUID key from the request header.
     * @param apiSecret The secret token from the request header.
     * @return UUID of the associated Application, or null if invalid.
     * @throws SQLException if a database error occurs.
     */
    public UUID getAppId(String apiKey, String apiSecret) throws SQLException {
        if (apiKey == null || apiSecret == null) {
            return null;
        }

        // 1. Generate a unique cache key for this credential pair
        String cacheKey = apiKey + ":" + apiSecret;

        // 2. Return from cache if present
        if (appCache.containsKey(cacheKey)) {
            return appCache.get(cacheKey);
        }

        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        UUID appId = null;

        String sql = "SELECT app_id, key_value FROM api_keys WHERE id = ? AND status = 'ACTIVE'";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, UUID.fromString(apiKey));

            rs = pstmt.executeQuery();
            if (rs.next()) {
                String storedHash = rs.getString("key_value");
                if (new PasswordHasher().checkPassword(apiSecret, storedHash)) {
                    String appIdStr = rs.getString("app_id");
                    if (appIdStr != null) {
                        appId = UUID.fromString(appIdStr);
                        appCache.put(cacheKey, appId);
                    }
                }
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }

        return appId;
    }


    /**
     * Revokes an API key by setting its status to REVOKED and recording revocation details.
     */
    private void revokeApiKeyInDb(UUID keyId, UUID loginUserId, UUID effectiveFid) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        boolean success = false;

        // Soft delete/Revoke by updating status and recording metadata.
        // Hardening: the tenant predicate is applied unconditionally — even the shared
        // platform-ADMIN can only revoke a key within the tenant named by effectiveFid.
        String sql = "UPDATE api_keys SET status = 'REVOKED', revoked_at = NOW(), last_used_at = NOW() WHERE id = ? AND status != 'REVOKED' AND fiduciary_id = ?";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, keyId);
            pstmt.setObject(2, effectiveFid);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                // Check if it exists at all (optional), scoped to the effective tenant.
                if (getApiKeyDetailsFromDb(keyId, effectiveFid).isEmpty()) {
                    throw new SQLException("API Key not found.");
                }
            }
            success = true;
        } finally {
            pool.cleanup(null, pstmt, conn);
        }

        if (success) {
            InputProcessor.evictApiKeyCache(keyId.toString());
            new Audit().logEventAsync("ADMIN", ADMIN_FID_UUID, Constants.SERVICE_TYPE_ADMIN_CONSOLE, loginUserId, "REVOKE_KEY", "Key:"+keyId);
        }
    }

    /**
     * Updates the ACTIVE/INACTIVE/EXPIRED status of an existing key.
     */
    private void updateApiKeyStatusInDb(UUID keyId, String status, UUID fiduciaryId, UUID loginUserId) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        PoolDB pool = new PoolDB();
        boolean success = false;

        // F4: load the key first to enforce tenant ownership and the no-reactivation rule.
        // Caller is already DB-verified ADMIN (gated in the switch); tenant check is enforced explicitly below.
        Optional<JSONObject> keyDetails = getApiKeyDetailsFromDbUnscoped(keyId);
        if (keyDetails.isEmpty()) {
            throw new SQLException("API Key not found.");
        }
        // F4: prevent cross-tenant status changes even for an ADMIN.
        String keyFiduciaryId = (String) keyDetails.get().get("fiduciary_id");
        if (keyFiduciaryId == null || !keyFiduciaryId.equals(fiduciaryId.toString())) {
            throw new SQLException("API Key does not belong to the specified fiduciary.");
        }
        // F4: refuse reactivation of an INACTIVE/EXPIRED key; re-issuance must go through generate_api_key.
        String current = (String) keyDetails.get().get("status");
        if ("ACTIVE".equalsIgnoreCase(status) && ("INACTIVE".equalsIgnoreCase(current) || "EXPIRED".equalsIgnoreCase(current))) {
            throw new SQLException("Cannot reactivate an INACTIVE/EXPIRED key; issue a new key via generate_api_key.");
        }

        // F4: scope the UPDATE by fiduciary so it can only touch keys belonging to this tenant.
        String sql = "UPDATE api_keys SET status = ?, last_updated_at = NOW() WHERE id = ? AND fiduciary_id = ? AND status != 'REVOKED'";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, status.toUpperCase());
            pstmt.setObject(2, keyId);
            pstmt.setObject(3, fiduciaryId);

            int affectedRows = pstmt.executeUpdate();
            if (affectedRows == 0) {
                // Check if it exists at all and if it was already permanently revoked.
                Optional<JSONObject> postKeyDetails = getApiKeyDetailsFromDbUnscoped(keyId);
                if (postKeyDetails.isEmpty()) {
                    throw new SQLException("API Key not found.");
                }
                if (postKeyDetails.get().get("status").equals("REVOKED")) {
                    throw new SQLException("Cannot update status of a permanently REVOKED key.");
                }
            } else {
                success = true;
            }
            InputProcessor.evictApiKeyCache(keyId.toString());
        } finally {
            pool.cleanup(null, pstmt, conn);
        }

        if (success) {
            new Audit().logEventAsync("ADMIN", ADMIN_FID_UUID, Constants.SERVICE_TYPE_ADMIN_CONSOLE, loginUserId, "UPDATE_API_KEY_STATUS", "Key:"+keyId+" status:"+status.toUpperCase());
        }
    }

    /**
     * Retrieves a list of API keys for a specific Fiduciary, with filtering.
     */
    private JSONArray listApiKeysFromDb(String fiduciaryId, String statusFilter, String search) throws SQLException {
        JSONArray keysArray = new JSONArray();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        // Select metadata columns (excluding the hash)
        StringBuilder sqlBuilder = new StringBuilder("SELECT ak.id, ak.fiduciary_id, ak.app_id, ak.description, ak.status, ak.permissions, ak.created_at, ak.expires_at, ak.last_used_at, ap.name FROM api_keys ak, apps ap WHERE ak.app_id=ap.id");
        List<Object> params = new ArrayList<>();

        if (fiduciaryId != null && !fiduciaryId.isEmpty()) {
            // ak. qualifier REQUIRED: api_keys ak + apps ap both have fiduciary_id/status
            // -> a bare column is ambiguous -> 500 "column reference fiduciary_id is
            // ambiguous" (browser-confirmed on the API Keys page). (vAIb)
            sqlBuilder.append(" AND ak.fiduciary_id = ?");
            params.add(fiduciaryId);
        }
        if (statusFilter != null && !statusFilter.isEmpty()) {
            sqlBuilder.append(" AND ak.status = ?");
            params.add(statusFilter.toUpperCase());
        }
        if (search != null && !search.isEmpty()) {
            sqlBuilder.append(" AND ak.description LIKE ?");
            params.add("%" + search + "%");
        }
        sqlBuilder.append(" ORDER BY created_at DESC");

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sqlBuilder.toString());
            for (int i = 0; i < params.size(); i++) {
                pstmt.setObject(i + 1, params.get(i));
            }
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject key = new JSONObject();
                key.put("key_id", rs.getString("id"));
                key.put("fiduciary_id", rs.getString("fiduciary_id"));
                key.put("app_id", rs.getString("app_id"));
                key.put("app_name", rs.getString("name"));
                key.put("description", rs.getString("description"));
                key.put("status", rs.getString("status"));
                key.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                key.put("expires_at", rs.getTimestamp("expires_at") != null ? rs.getTimestamp("expires_at").toInstant().toString() : null);
                key.put("last_used_at", rs.getTimestamp("last_used_at") != null ? rs.getTimestamp("last_used_at").toInstant().toString() : null);

                keysArray.add(key);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return keysArray;
    }
}
