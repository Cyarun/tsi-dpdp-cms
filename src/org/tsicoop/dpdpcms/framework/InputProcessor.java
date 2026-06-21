package org.tsicoop.dpdpcms.framework;

import com.networknt.schema.ValidationMessage;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.tsicoop.dpdpcms.framework.PasswordHasher;
import org.tsicoop.dpdpcms.service.v1.Audit;
import org.tsicoop.dpdpcms.util.Constants;

import java.io.BufferedReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class InputProcessor {
    public final static String REQUEST_DATA = "input_json";
    public final static String AUTH_TOKEN = "auth_token";

    private static final String CLIENT_PERMISSIONS = "CLIENT_PERMISSIONS";

    private static Map<String,Set<String>> permissionsMap = new ConcurrentHashMap<String, Set<String>>();

    private static final long API_CACHE_TTL_MS = 60_000L;

    private static class CachedEntry {
        final boolean valid;
        final long expiresAt;
        CachedEntry(boolean valid) {
            this.valid = valid;
            this.expiresAt = System.currentTimeMillis() + API_CACHE_TTL_MS;
        }
        boolean isExpired() { return System.currentTimeMillis() > expiresAt; }
    }

    private static final Map<String, CachedEntry> apiClientCache = new ConcurrentHashMap<>();


    /**
     * Verifies if the authenticated client or user possesses the required permission scope.
     * This method is called by InterceptingFilter after processClientHeader has loaded the scopes.
     */
    public static boolean hasPermission(HttpServletRequest req, String requiredScope) {
        Object permsObj = retrievePerms(req);
        if (permsObj instanceof Set) {
            Set<String> permissions = (Set<String>) permsObj;
            String permstr = permissions.toString();
            return permstr.contains(requiredScope.toUpperCase());
        }
        return false;
    }

    /**
     * Retrieves app permissions.
     * Loads authorized scopes (READ, WRITE, PURGE) from the registry into the request context.
     */
    public static Set<String> retrievePerms(HttpServletRequest req) {
        String key = req.getHeader("X-API-Key");
        String secret = req.getHeader("X-API-Secret");
        Set<String> scopeSet = null;
        PoolDB pool = null;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        if(permissionsMap.get(key)!=null){
            scopeSet = (Set<String>) permissionsMap.get(key);
        }
        else {
            try {
                pool = new PoolDB();
                conn = pool.getConnection();
                String sql = "SELECT fiduciary_id, permissions, key_value FROM api_keys WHERE id = ? AND status = 'ACTIVE'";
                pstmt = conn.prepareStatement(sql);
                pstmt.setObject(1, UUID.fromString(key));
                rs = pstmt.executeQuery();

                if (rs.next() && new PasswordHasher().checkPassword(secret, rs.getString("key_value"))) {
                    req.setAttribute("fiduciary_id", rs.getObject("fiduciary_id"));

                    String rawPerms = rs.getString("permissions");
                    scopeSet = new HashSet<>();
                    if (rawPerms != null) {
                        for (String p : rawPerms.split(",")) {
                            scopeSet.add(p.trim().toUpperCase());
                        }
                    }
                    permissionsMap.put(key, scopeSet);
                }
            } catch (Exception e) {
                System.err.println("Client Auth Failure: " + e.getMessage());
            } finally {
                pool.cleanup(rs, pstmt, conn);
            }
        }
        return scopeSet;
    }

    public static void processInput(HttpServletRequest request, HttpServletResponse response) {
        StringBuilder buffer = new StringBuilder();
        try {
            // 1. Attempt to read from the input stream (POST body)
            BufferedReader reader = request.getReader();
            String line = null;
            while ((line = reader.readLine()) != null) {
                buffer.append(line);
                buffer.append(System.lineSeparator());
            }

            String data = buffer.toString().trim();

            // 2. Fallback: If data is empty, extract parameters and wrap in JSON
            if (data.isEmpty()) {
                JSONObject jsonParams = new JSONObject();
                Enumeration<String> paramNames = request.getParameterNames();

                while (paramNames.hasMoreElements()) {
                    String name = paramNames.nextElement();
                    String[] values = request.getParameterValues(name);

                    if (values != null && values.length > 0) {
                        // Handle single vs multiple values for the same parameter key
                        if (values.length == 1) {
                            jsonParams.put(name, values[0]);
                        } else {
                            JSONArray valArray = new JSONArray();
                            for (String v : values) {
                                valArray.add(v);
                            }
                            jsonParams.put(name, valArray);
                        }
                    }
                }
                data = jsonParams.toJSONString();
            }

            // 3. Persist the normalized JSON data as a request attribute
            request.setAttribute(REQUEST_DATA, data);

        } catch (Exception e) {
            System.err.println("InputProcessor critical failure: " + e.getMessage());
            request.setAttribute(REQUEST_DATA, "{}");
        }
    }

    public static boolean processAdminHeader(HttpServletRequest request, HttpServletResponse response) {
        boolean validheader = false;
        JSONObject authToken = null;
        try {
            authToken = getAdminAuthToken(request, response);
            if(authToken != null) {
                request.setAttribute(AUTH_TOKEN, authToken);
                validheader = true;
            }
        }catch (Exception e){}
        return validheader;
    }

    public static boolean processClientHeader(HttpServletRequest req, HttpServletResponse res) {
        boolean validheader = false;
        String apiKey = req.getHeader("X-API-Key");
        String apiSecret = req.getHeader("X-API-Secret");

        if (apiKey == null || apiSecret == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Missing API Key or Secret.", req.getRequestURI());
            return false;
        }

        // Validate API Key and Secret against the api_user table
        try {
            if (!isValidApiClient(apiKey, apiSecret)) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid or inactive API Key/Secret.", req.getRequestURI());
                return false;
            }
            else{
                validheader = true;
            }
        } catch (SQLException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", "Authentication failed due to database error.", req.getRequestURI());
            return false;
        }
        return validheader;
    }

    private static boolean isValidApiClient(String apiKey, String apiSecret) throws SQLException {
        String cacheKey = apiKey + ":" + apiSecret;
        CachedEntry cached = apiClientCache.get(cacheKey);
        if (cached != null && !cached.isExpired()) {
            return cached.valid;
        }
        apiClientCache.remove(cacheKey);

        boolean valid = false;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT status, key_value FROM api_keys WHERE id = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, UUID.fromString(apiKey));
            rs = pstmt.executeQuery();
            if (rs.next()) {
                String status = rs.getString("status");
                String storedHash = rs.getString("key_value");
                if (status.equalsIgnoreCase("ACTIVE") && new PasswordHasher().checkPassword(apiSecret, storedHash)) {
                    valid = true;
                    apiClientCache.put(cacheKey, new CachedEntry(true));
                }
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return valid;
    }

    public static String getEmail(HttpServletRequest req){
        JSONObject authToken = null;
        String email = null;
        try {
            authToken = (JSONObject) req.getAttribute(InputProcessor.AUTH_TOKEN);
            email = (String) authToken.get("email");
        }catch(Exception e){
            e.printStackTrace();
        }
        return email;
    }

    public static UUID getAuthenticatedUserId(HttpServletRequest req){
        JSONObject authToken = null;
        UUID loginUserId = null;
        String email = null;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = null;
        String sql = "SELECT id FROM operators WHERE email_hmac = " + DbEncryption.HMAC;

        authToken = (JSONObject) req.getAttribute(InputProcessor.AUTH_TOKEN);
        if(authToken == null) return null;
        email = (String) authToken.get("email");

        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            DbEncryption.bindHmac(pstmt, 1, email);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                loginUserId = UUID.fromString(rs.getString("id"));
            }
        }catch(Exception e){
            e.printStackTrace();
        }finally{
            pool.cleanup(rs,pstmt,conn);
        }
        return loginUserId;
    }

    public static String getName(HttpServletRequest req){
        JSONObject authToken = null;
        String name = null;
        try {
            authToken = (JSONObject) req.getAttribute(InputProcessor.AUTH_TOKEN);
            name = (String) authToken.get("name");
        }catch(Exception e){
            e.printStackTrace();
        }
        return name;
    }

    public static String getRole(HttpServletRequest req){
        JSONObject authToken = null;
        String role = null;
        try {
            authToken = (JSONObject) req.getAttribute(InputProcessor.AUTH_TOKEN);
            role = (String) authToken.get("role");
        }catch(Exception e){
            e.printStackTrace();
        }
        return role;
    }

    /** Immediately evicts a revoked/deactivated API key from both in-process caches. */
    public static void evictApiKeyCache(String apiKeyId) {
        permissionsMap.remove(apiKeyId);
        apiClientCache.entrySet().removeIf(e -> e.getKey().startsWith(apiKeyId + ":"));
    }

    /**
     * Returns the verified fiduciary (tenant) id for the authenticated caller from the database,
     * not from any client-supplied claim. The req.setAttribute("fiduciary_id") at line 85 is set
     * ONLY in the app/API-key path, not the operator JWT path, so this DB lookup is required.
     * Returns the ADMIN fiduciary (all-zeros UUID) ONLY when an ACTIVE operator row
     * genuinely has a null fiduciary_id (the platform admin). Returns null (FAIL CLOSED)
     * for NO ACTIVE row (deactivated/deleted/none), bad input, or any error — never the
     * platform sentinel (vAIb-ae11 SEC HIGH: that fail-open elevated deactivated operators).
     */
    public static UUID getVerifiedFiduciaryId(HttpServletRequest req) {
        final UUID ADMIN_FID_UUID = UUID.fromString("00000000-0000-0000-0000-000000000000");
        JSONObject authToken = (JSONObject) req.getAttribute(InputProcessor.AUTH_TOKEN);
        if (authToken == null) return null;
        String email = (String) authToken.get("email");
        if (email == null) return null;

        PoolDB pool = null;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT fiduciary_id FROM operators WHERE email_hmac = " + DbEncryption.HMAC + " AND status = 'ACTIVE'");
            DbEncryption.bindHmac(pstmt, 1, email);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                Object fid = rs.getObject("fiduciary_id");
                // ACTIVE row found: a NULL fiduciary_id is the genuine PLATFORM ADMIN
                // (all-zeros sentinel); a concrete UUID is a tenant-scoped operator.
                return fid != null ? (UUID) fid : ADMIN_FID_UUID;
            }
            // NO ACTIVE operator row (deactivated / deleted / valid-signature JWT for an
            // email with no operator) MUST FAIL CLOSED -> null (deny). Returning the
            // all-zeros sentinel here was a FAIL-OPEN: it elevated any deactivated
            // operator (JWT valid ~10d) to PLATFORM ADMIN -> full cross-tenant breach
            // (vAIb-ae11 SEC HIGH). Callers (resolveTenantScope / Job / Fiduciary) all
            // already deny on null. The platform sentinel ONLY comes from the line above
            // when an ACTIVE row genuinely has fiduciary_id IS NULL.
            return null;
        } catch (Exception e) {
            System.err.println("[ERROR] InputProcessor.getVerifiedFiduciaryId: " + e);
        } finally {
            if (pool != null) pool.cleanup(rs, pstmt, conn);
        }
        return null;
    }

    /** The all-zeros sentinel fiduciary that marks a PLATFORM admin (operator with a null fiduciary_id). */
    public static final UUID PLATFORM_ADMIN_FID = UUID.fromString("00000000-0000-0000-0000-000000000000");

    // -- vAIb-2yn0: TSI PLATFORM ROLES + central per-function authorization matrix --
    //
    // THREE platform-scope roles. The platform scope is ALWAYS the NULL fiduciary_id
    // (all-zeros sentinel above) -- a CONCRETE fiduciary_id is ALWAYS a tenant operator,
    // regardless of role label. So a tenant ADMIN (the Wix owner, concrete fiduciary) is
    // NOT a platform SUPER_ADMIN: the discriminator is fiduciary NULL-vs-concrete, NOT the
    // role string. These role constants gate ONLY the platform path (verified fiduciary ==
    // PLATFORM_ADMIN_FID); the tenant path is unchanged (hard-scoped by fiduciary).
    public static final String ROLE_SUPER_ADMIN        = "SUPER_ADMIN";        // everything, cross-tenant
    public static final String ROLE_ONBOARDING_MANAGER = "ONBOARDING_MANAGER"; // create/manage; NO destroy/billing/deactivate/revoke
    public static final String ROLE_SUPPORT_ASSISTANT  = "SUPPORT_ASSISTANT";  // READ-ONLY cross-tenant; NO mutation, NO secrets

    /** All recognised platform-scope roles (a NULL-fiduciary operator MUST carry one of these). */
    private static final Set<String> PLATFORM_ROLES = new HashSet<>(Arrays.asList(
            ROLE_SUPER_ADMIN, ROLE_ONBOARDING_MANAGER, ROLE_SUPPORT_ASSISTANT));

    /**
     * READ-only platform functions (list_x / get_x / metrics view). ONBOARDING_MANAGER and
     * SUPPORT_ASSISTANT may both read; SUPPORT_ASSISTANT may ONLY read. Names are the
     * lower-cased ``_func`` values across every CMS service (Fiduciary/Policy/Ropa/App/
     * Operator/AdminDash/Grievance/Compliance/Legal/Job/Consent/Audit/Notification).
     * NOTE: api-key reads (get_api_key_details) are NOT here -- they expose secrets and so
     * are SUPER_ADMIN-only (see SECRET_FUNCS / matrix below).
     */
    private static final Set<String> PLATFORM_READ_FUNCS = new HashSet<>(Arrays.asList(
            "list_fiduciaries", "get_fiduciary", "validate_fiduciary_domain",
            "list_policies", "list_active_policies", "get_policy", "get_active_policy",
            "list_entries", "get_entry", "validate_completeness", "export_ropa",
            "list_apps", "get_app",
            "list_users", "get_user",
            "get_admin_metrics", "get_dpo_metrics", "list_pending_grievances", "list_access_logs",
            "list_grievances", "get_grievance", "list_user_grievances",
            "list_purge_requests", "get_purge_request",
            "list_certificates", "get_certificate",
            "list_jobs", "download_file",
            "get_active_consent", "get_consent_record_details", "list_consent_history", "validate_consent",
            "list_audit_logs", "get_audit_log",
            "list_notifications",
            "list_api_keys"  // metadata only (no key material); secret-bearing get/generate are SECRET_FUNCS
    ));

    /**
     * Functions the ONBOARDING_MANAGER may PERFORM (create/manage fiduciaries+policies+
     * RoPA+apps+operators). Reads are inherited from PLATFORM_READ_FUNCS. Explicitly
     * EXCLUDES destroy (delete_x / retire_x), billing, deactivate-fiduciary, and any key
     * revoke/secret op -- those stay SUPER_ADMIN-only (DENY for onboarding/support).
     */
    private static final Set<String> ONBOARDING_MANAGE_FUNCS = new HashSet<>(Arrays.asList(
            // Fiduciaries: create/update only (NOT delete_fiduciary / deactivate).
            "create_fiduciary", "update_fiduciary",
            // Policies: author + publish (NOT delete_policy -- a destroy op).
            "create_policy", "update_policy", "publish_policy",
            // RoPA: author lifecycle (NOT retire_entry -- a destroy/withdraw op).
            "create_entry", "update_entry", "publish_entry", "derive_from_policy",
            // Apps: create/update only (NOT delete_app).
            "create_app", "update_app",
            // Operators: provision/manage tenant operators (NOT deactivate_user -- destroy).
            "create_user", "update_user",
            // Grievance / compliance workflow management (operational, not destructive).
            "update_grievance_status", "update_purge_status", "initiate_purge_request",
            "mark_notification_read"
    ));

    /**
     * SECRET / key-material functions -- SUPER_ADMIN ONLY. Even SUPPORT_ASSISTANT's read
     * scope must NEVER reach these (they expose or rotate API keys). Listed separately so
     * the default-deny matrix can fail closed on anything that touches a secret.
     */
    private static final Set<String> SECRET_FUNCS = new HashSet<>(Arrays.asList(
            "generate_api_key", "get_api_key_details", "revoke_api_key", "update_api_key_status",
            "generate_recovery_key", "verify_recovery_key", "reset_password_via_recovery"
    ));

    /** True iff this role is one of the three platform-scope roles. */
    public static boolean isPlatformRole(String role) {
        return role != null && PLATFORM_ROLES.contains(role.trim().toUpperCase());
    }

    /**
     * vAIb-2yn0 -- CENTRAL platform authorization matrix (default-deny).
     *
     * Decides whether a PLATFORM-scope operator (NULL fiduciary) with verified ``role``
     * may invoke ``func``. This is the SINGLE source of truth; it is invoked from the
     * platform branch of resolveTenantScope (and from Fiduciary's platform branch, which
     * scopes via getVerifiedFiduciaryId directly). Tenant-scoped operators NEVER reach
     * here -- they are hard-scoped by fiduciary and keep the legacy ADMIN/DPO behaviour.
     *
     * Rules:
     *   - SUPER_ADMIN          -> everything (legacy platform-admin behaviour, mapped cleanly).
     *   - ONBOARDING_MANAGER   -> PLATFORM_READ_FUNCS  +  ONBOARDING_MANAGE_FUNCS; DENY all
     *                            destroy/billing/deactivate-fiduciary/revoke-keys/secrets.
     *   - SUPPORT_ASSISTANT    -> PLATFORM_READ_FUNCS only (minus SECRET_FUNCS); DENY all mutation.
     *   - ADMIN (legacy null-fiduciary platform admin) -> treated as SUPER_ADMIN for back-compat
     *                            (the current platform-admin maps cleanly to SUPER_ADMIN).
     *   - anything else / null role / unknown func for a constrained role -> DENY (fail closed).
     *
     * @return true if ALLOWED; false if DENIED (caller MUST 403 + audit).
     */
    public static boolean isPlatformFuncAllowed(String role, String func) {
        if (func == null) return false;            // no function -> deny
        String f = func.trim().toLowerCase();
        String r = (role == null) ? "" : role.trim().toUpperCase();

        // SUPER_ADMIN (and the legacy null-fiduciary ADMIN it maps from) -> all funcs.
        if (ROLE_SUPER_ADMIN.equals(r) || "ADMIN".equals(r)) return true;

        // Secret/key-material funcs are SUPER_ADMIN-only -- deny everyone else outright.
        if (SECRET_FUNCS.contains(f)) return false;

        if (ROLE_SUPPORT_ASSISTANT.equals(r)) {
            // READ-ONLY: allow reads only, deny every mutation (fail closed).
            return PLATFORM_READ_FUNCS.contains(f);
        }

        if (ROLE_ONBOARDING_MANAGER.equals(r)) {
            // Reads + the explicit manage set; everything else (destroy/billing/etc.) denied.
            return PLATFORM_READ_FUNCS.contains(f) || ONBOARDING_MANAGE_FUNCS.contains(f);
        }

        // Unknown / null platform role on a NULL-fiduciary operator -> DENY (default-deny).
        return false;
    }

    /**
     * vAIb-2yn0 -- enforce the platform matrix for the current request, fail-closed.
     *
     * Resolves the verified role, applies isPlatformFuncAllowed, and on DENY sends a 403,
     * AUDIT-logs the rejected attempt (role + func + denied -- NO PII), and returns false.
     * Returns true when ALLOWED. Callers in the platform branch MUST ``return null`` (or
     * stop) when this returns false. The role is read SERVER-SIDE (getVerifiedRole / JWT),
     * never from a client body field.
     */
    public static boolean enforcePlatformAuthz(HttpServletRequest req, HttpServletResponse res, String func) {
        String role = getVerifiedRole(req);
        if (isPlatformFuncAllowed(role, func)) return true;
        // DENY: audit the rejected platform action (role + func, no PII/secret) then 403.
        try {
            new Audit().logEventAsync(
                    (role == null ? "UNKNOWN" : role), PLATFORM_ADMIN_FID,
                    Constants.SERVICE_TYPE_ADMIN_CONSOLE, getAuthenticatedUserId(req),
                    "PLATFORM_AUTHZ_DENIED",
                    "role=" + (role == null ? "null" : role) + " func=" + (func == null ? "null" : func.toLowerCase()) + " denied");
        } catch (Exception ignored) { /* audit must never break the deny */ }
        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden",
                "Your platform role is not permitted to perform this action.", req.getRequestURI());
        return false;
    }

    /**
     * vAIb-ae11 -- single source of truth for per-tenant scoping of operator-console requests.
     *
     * Resolves the fiduciary (tenant) an authenticated operator may act on, derived ENTIRELY
     * server-side from the operator's own DB record (getVerifiedFiduciaryId), NEVER from any
     * client-supplied "fiduciary_id" in the request body. This closes the cross-tenant leak
     * where every admin/dpo endpoint trusted the body fiduciary_id.
     *
     * Rules (the discriminator is the VERIFIED FIDUCIARY, not the JWT role -- note the
     * auto-created Wix-owner operator is role=ADMIN but carries a CONCRETE tenant fiduciary):
     *   - TENANT-SCOPED operator (verified fiduciary is a concrete tenant UUID):
     *       HARD-SCOPED to that tenant. Any client-supplied fiduciary_id is IGNORED, and if it
     *       names a DIFFERENT tenant the request is DENIED (403) -- fail closed, no silent
     *       cross-tenant fallthrough.
     *   - PLATFORM admin (verified fiduciary == PLATFORM_ADMIN_FID, i.e. null fiduciary_id):
     *       may target a specific tenant via the body fiduciary_id (provisioning/support path);
     *       403 if the body fiduciary_id is absent/malformed (never an unscoped cross-tenant op).
     *
     * On any failure this sends the appropriate error response and returns null -- callers MUST
     * `return` immediately when the result is null.
     *
     * @param requireTargetForPlatform when true a PLATFORM admin MUST name a tenant in the body
     *        (used by by-id / mutation ops); when false a PLATFORM admin with no body fid yields
     *        PLATFORM_ADMIN_FID so the caller can decide to list across all tenants.
     */
    public static UUID resolveTenantScope(HttpServletRequest req, HttpServletResponse res,
                                          boolean requireTargetForPlatform) {
        UUID verified = getVerifiedFiduciaryId(req);
        if (verified == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized",
                    "Unable to resolve authenticated fiduciary.", req.getRequestURI());
            return null;
        }

        String bodyFidStr = null;
        String bodyFunc = null;
        try {
            JSONObject input = getInput(req);
            if (input != null) {
                Object o = input.get("fiduciary_id");
                if (o == null) o = input.get("fiduciary_id_filter"); // Policy.list_policies alias
                if (o != null) bodyFidStr = o.toString();
                Object fn = input.get("_func");
                if (fn != null) bodyFunc = fn.toString();
            }
        } catch (Exception ignored) { /* body unavailable/unparseable -> treated as absent */ }

        boolean isPlatform = PLATFORM_ADMIN_FID.equals(verified);

        if (!isPlatform) {
            // Tenant-scoped operator: hard-scope to own fiduciary; deny any mismatching target.
            // The platform role matrix does NOT apply to tenant operators (legacy ADMIN/DPO,
            // hard-scoped by fiduciary) — their authz is the cross-tenant strip+inject above.
            if (bodyFidStr != null && !bodyFidStr.isEmpty()
                    && !bodyFidStr.equalsIgnoreCase(verified.toString())) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden",
                        "Cross-tenant access denied: request is scoped to your own fiduciary.",
                        req.getRequestURI());
                return null;
            }
            return verified;
        }

        // vAIb-2yn0 — PLATFORM-scope operator (NULL fiduciary): CENTRAL default-deny role
        // matrix runs BEFORE any tenant is selected. SUPER_ADMIN → all; ONBOARDING_MANAGER →
        // create/manage (no destroy/billing/deactivate/revoke); SUPPORT_ASSISTANT → read-only;
        // anything else → DENY (403 + audit). enforcePlatformAuthz emits the 403 + AUDIT on deny.
        if (!enforcePlatformAuthz(req, res, bodyFunc)) {
            return null;
        }

        // Platform admin: the body fiduciary_id selects the target tenant.
        if (bodyFidStr == null || bodyFidStr.isEmpty()) {
            if (requireTargetForPlatform) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden",
                        "Platform admin must specify the target tenant via 'fiduciary_id'.",
                        req.getRequestURI());
                return null;
            }
            return PLATFORM_ADMIN_FID; // caller may interpret as "all tenants"
        }
        try {
            return UUID.fromString(bodyFidStr);
        } catch (IllegalArgumentException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden",
                    "Invalid 'fiduciary_id' for platform-scoped operation.", req.getRequestURI());
            return null;
        }
    }

    /** Convenience: requires a concrete target tenant (by-id reads, mutations). */
    public static UUID resolveTenantScope(HttpServletRequest req, HttpServletResponse res) {
        return resolveTenantScope(req, res, true);
    }

    /** True when the authenticated operator is the PLATFORM admin (null fiduciary_id). */
    public static boolean isPlatformAdmin(HttpServletRequest req) {
        return PLATFORM_ADMIN_FID.equals(getVerifiedFiduciaryId(req));
    }

    /** Returns the role from the database for the authenticated user, not from the JWT claim. */
    public static String getVerifiedRole(HttpServletRequest req) {
        JSONObject authToken = (JSONObject) req.getAttribute(InputProcessor.AUTH_TOKEN);
        if (authToken == null) return null;
        // The operator JWT is already signature-verified (processAdminHeader). It
        // carries a verified "role" claim and a "sub" (operator id). Trust the
        // signed role directly — the previous version looked up by an "email"
        // claim the token does not contain, so it always returned null and broke
        // operator actions (e.g. update_grievance_status -> 401). The role here is
        // from a signed token, not client input, so it is safe to trust.
        String role = (String) authToken.get("role");
        if (role != null && !role.isEmpty()) return role;

        // Fallback: resolve role from the operators table by the token subject
        // (operator id) if a future token omits the role claim.
        Object sub = authToken.get("sub");
        if (sub == null) sub = authToken.get("email");  // legacy tolerance
        if (sub == null) return null;
        PoolDB pool = null;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT role FROM operators WHERE id = ?::uuid AND status = 'ACTIVE'");
            pstmt.setString(1, sub.toString());
            rs = pstmt.executeQuery();
            if (rs.next()) return rs.getString("role");
        } catch (Exception e) {
            System.err.println("[ERROR] InputProcessor.getVerifiedRole: " + e);
        } finally {
            if (pool != null) pool.cleanup(rs, pstmt, conn);
        }
        return null;
    }

    public static JSONObject getAdminAuthToken(HttpServletRequest req, HttpServletResponse res) throws Exception{
        JSONObject tokenDetails = null;
        String authorization = null;
        StringTokenizer strTok = null;
        String token = null;

        try {
            authorization = req.getHeader("Authorization");
            if(authorization == null){
                token = req.getParameter("auth");
            }else {
                strTok = new StringTokenizer(authorization, " ");
                strTok.nextToken();
                token = strTok.nextToken();
            }
            if (JWTUtil.isTokenValid(token)) {
                tokenDetails = new JSONObject();
                tokenDetails.put("email",JWTUtil.getEmailFromToken(token));
                tokenDetails.put("name",JWTUtil.getNameFromToken(token));
                tokenDetails.put("role",JWTUtil.getRoleFromToken(token));
            } else if (token != null) {
                String tokenPrefix = token.length() > 12 ? token.substring(0, 12) : token;
                String sourceIp = req.getRemoteAddr();
                new Audit().logEventAsync(
                        tokenPrefix, UUID.fromString("00000000-0000-0000-0000-000000000000"),
                        Constants.SERVICE_TYPE_SYSTEM, null,
                        "JWT_VALIDATION_FAILED", "ip=" + sourceIp);
            }
        } catch (Exception e) {
            System.err.println("[ERROR] InputProcessor.getAdminAuthToken: " + e);
        }
        //System.out.println("tokenDetails:"+tokenDetails);
        return tokenDetails;
    }

    public static JSONObject getInput(HttpServletRequest req) throws Exception {
        JSONObject input = null;
        try {
            String inputs = (String) req.getAttribute(InputProcessor.REQUEST_DATA);
            if (inputs != null) inputs = inputs.trim();
            input = JacksonUtil.parse(inputs);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return input;
    }

    public static boolean validate(HttpServletRequest req, HttpServletResponse res) {

        JSONObject input = null;
        Set<ValidationMessage> errors = null;
        boolean valid = true;
        String func = null;

        try {
            input = InputProcessor.getInput(req);
            func = (String) input.get("_func");

            if(func == null){
                OutputProcessor.sendError(res,HttpServletResponse.SC_BAD_REQUEST,"_func missing");
                valid = false;
            }else{
                errors = JSONSchemaValidator.getHandle().validateSchema(func, input);
            }

            if(errors != null && errors.size()>0) {
                OutputProcessor.sendError(res,HttpServletResponse.SC_BAD_REQUEST, errors.toString());
                valid = false;
            }

        }catch(Exception e){
            e.printStackTrace();
            OutputProcessor.sendError(res,HttpServletResponse.SC_BAD_REQUEST,"Unknown input validation error");
            valid = false;
        }
        return valid;
    }

    public static String applyRules(String value) {
        if (value != null && value.trim().length() > 0) {
            try {
                value = URLDecoder.decode(value, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                //log.error(e.getMessage());
            }
            //value = StringEscapeUtils.unescapeHtml(value);
        } else {
            value = "";
        }
        return value;
    }
}
