package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;

/**
 * Data Principal self-service portal authentication service.
 * Exposes public endpoints (no auth required) for:
 *   - principal_login: authenticate with fiduciary_id + user_id + OTP, returns a PRINCIPAL JWT
 *   - list_active_fiduciaries: public listing of active fiduciaries for portal dropdown
 */
public class Principal implements Action {

    /**
     * Shared secret that gates principal_login (vAIb-4y7x).
     *
     * principal_login is a PUBLIC/no-auth endpoint, so the `otp` field IS the auth:
     * the REAL per-principal OTP gate lives in the fabric (gateway) — it verifies the
     * data principal's 6-digit code (constant-time hash compare, single-use, TTL) and
     * ONLY THEN calls principal_login, passing THIS shared secret as `otp`. The CMS
     * therefore trusts the call iff the caller proves it knows the secret. An attacker
     * hitting the CMS directly with a guessed/empty otp does NOT know it -> rejected.
     *
     * Read from the PRINCIPAL_LOGIN_SECRET env var — same discipline as JWT_SECRET
     * (JWTUtil) and DB_ENCRYPTION_KEY (DbEncryption): the value is NEVER hardcoded and
     * NEVER logged. FAIL CLOSED: if the env var is unset/empty the secret is null and
     * EVERY principal_login is rejected (we never fall back to a default — an empty or
     * default value would re-open the bypass). The compare is constant-time
     * (MessageDigest.isEqual) so the secret cannot be recovered via timing.
     *
     * FOLLOW-UP (vAIb-4y7x, noted): a stronger future fix is the fabric minting a
     * short-lived signed JWT the CMS verifies (bound to user_id + fiduciary_id + exp);
     * the shared-secret check closes the live hole now with the smallest diff.
     */
    private static final byte[] PRINCIPAL_LOGIN_SECRET = loadPrincipalLoginSecret();

    private static byte[] loadPrincipalLoginSecret() {
        String secret = System.getenv("PRINCIPAL_LOGIN_SECRET");
        if (secret == null || secret.trim().isEmpty()) {
            // FAIL CLOSED: no secret configured -> reject all principal_login. Do NOT
            // throw at class-load (that would also break list_active_fiduciaries); the
            // null is checked per-request in handleLogin and rejects fail-closed.
            System.err.println("SECURITY: PRINCIPAL_LOGIN_SECRET is not set — "
                    + "principal_login is DISABLED (fail closed). Set it to the value "
                    + "provisioned in OpenBao (vaib/cms/principal_login_secret).");
            return null;
        }
        return secret.trim().getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input;
        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing '_func'.", req.getRequestURI());
                return;
            }

            switch (func.toLowerCase()) {
                case "list_active_fiduciaries":
                    JSONArray fiduciaries = listActiveFiduciaries();
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, fiduciaries);
                    break;

                case "principal_login":
                    handleLogin(input, req, res);
                    break;

                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown function: " + func, req.getRequestURI());
            }
        } catch (SQLException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage(), req.getRequestURI());
        }
    }

    private void handleLogin(JSONObject input, HttpServletRequest req, HttpServletResponse res) throws SQLException {
        String fiduciaryIdStr = (String) input.get("fiduciary_id");
        String userId = (String) input.get("user_id");
        String otp = (String) input.get("otp");

        if (fiduciaryIdStr == null || fiduciaryIdStr.isEmpty() || userId == null || userId.isEmpty() || otp == null || otp.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "fiduciary_id, user_id, and otp are required.", req.getRequestURI());
            return;
        }

        // principal_login is gated by the fabric-shared secret (vAIb-4y7x). FAIL CLOSED
        // if the secret is unconfigured (null) so a missing env can never re-open the
        // bypass. Constant-time compare (MessageDigest.isEqual) so the secret cannot be
        // recovered via response timing. The real per-principal OTP was already proven
        // by the fabric BEFORE this call; this check authenticates the FABRIC, not the
        // principal's typed code.
        if (PRINCIPAL_LOGIN_SECRET == null
                || !MessageDigest.isEqual(PRINCIPAL_LOGIN_SECRET, otp.getBytes(StandardCharsets.UTF_8))) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid OTP.", req.getRequestURI());
            return;
        }

        UUID fiduciaryId;
        try {
            fiduciaryId = UUID.fromString(fiduciaryIdStr);
        } catch (IllegalArgumentException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid fiduciary_id format.", req.getRequestURI());
            return;
        }

        // Validate fiduciary is ACTIVE
        String fiduciaryName = getActiveFiduciaryName(fiduciaryId);
        if (fiduciaryName == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Fiduciary not found or inactive.", req.getRequestURI());
            return;
        }

        // Fetch all active policies for this fiduciary
        JSONArray policies = getActivePolicies(fiduciaryId);

        // Generate principal portal token
        String token = JWTUtil.generatePrincipalToken(userId, fiduciaryIdStr);

        // Audit the login
        new Audit().logEventAsync(userId, fiduciaryId, "PRINCIPAL_PORTAL", null, "PRINCIPAL_LOGIN", "Portal login for " + userId);

        JSONObject response = new JSONObject();
        response.put("success", true);
        response.put("token", token);
        response.put("user_id", userId);
        response.put("fiduciary_id", fiduciaryIdStr);
        response.put("fiduciary_name", fiduciaryName);
        response.put("policies", policies);
        OutputProcessor.send(res, HttpServletResponse.SC_OK, response);
    }

    private JSONArray listActiveFiduciaries() throws SQLException {
        JSONArray result = new JSONArray();
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        String sql = "SELECT id, name FROM fiduciaries WHERE status = 'ACTIVE' ORDER BY name ASC";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject fid = new JSONObject();
                fid.put("fiduciary_id", rs.getString("id"));
                fid.put("name", rs.getString("name"));
                result.add(fid);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return result;
    }

    private String getActiveFiduciaryName(UUID fiduciaryId) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        String sql = "SELECT name FROM fiduciaries WHERE id = ? AND status = 'ACTIVE'";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            rs = pstmt.executeQuery();
            if (rs.next()) return rs.getString("name");
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return null;
    }

    private JSONArray getActivePolicies(UUID fiduciaryId) throws SQLException {
        JSONArray result = new JSONArray();
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        String sql = "SELECT id, version, jurisdiction, effective_date, policy_content " +
                "FROM consent_policies WHERE fiduciary_id = ? AND status = 'ACTIVE' AND effective_date <= NOW() " +
                "ORDER BY effective_date DESC";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject entry = new JSONObject();
                entry.put("policy_id", rs.getString("id"));
                entry.put("version", rs.getString("version"));
                entry.put("jurisdiction", rs.getString("jurisdiction"));
                entry.put("effective_date", rs.getTimestamp("effective_date").toInstant().toString());
                entry.put("title", extractPolicyTitle(rs.getString("policy_content")));
                result.add(entry);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return result;
    }

    private String extractPolicyTitle(String policyContentJson) {
        try {
            org.json.simple.JSONObject map = (org.json.simple.JSONObject)
                    new org.json.simple.parser.JSONParser().parse(policyContentJson);
            org.json.simple.JSONObject lc = map.containsKey("en")
                    ? (org.json.simple.JSONObject) map.get("en")
                    : (org.json.simple.JSONObject) map.values().iterator().next();
            if (lc != null && lc.containsKey("title")) return (String) lc.get("title");
        } catch (Exception ignored) {}
        return "Privacy Policy";
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed", "Only POST is supported.", req.getRequestURI());
            return false;
        }
        return InputProcessor.validate(req, res);
    }
}
