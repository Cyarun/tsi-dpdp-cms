package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import java.sql.*;
import java.util.UUID;
import java.time.Instant;

/**
 * Wallet handles lifecycle commands originating from the user's Portable Wallet.
 * Maintains provenance by recording a new immutable consent artifact for every action.
 * Background purging (CES) is triggered by flagging the principal in data_principal
 * (last_ces_run = NULL) so the CES batch job re-evaluates and creates the purge_requests.
 * Every protected command is scoped to a single principal via the signed SYNC token —
 * userId and fiduciaryId come from the token, never the request body.
 */
public class Wallet implements Action {

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        try {
            JSONObject input = InputProcessor.getInput(req);
            String command = (String) input.get("command");
            String syncToken = (String) input.get("sync_token");
            String fiduciaryIdStr = (String) input.get("fiduciary_id");
            String userId = (String) input.get("user_id"); // DYNAMIC: Identity passed from Wallet

            if (command == null) {
                OutputProcessor.errorResponse(res, 400, "Bad Request", "Missing command.", req.getRequestURI());
                return;
            }

            // Utility function: Get Fiduciary Name (Non-authenticated context)
            if ("GET_FIDUCIARY_NAME".equalsIgnoreCase(command)) {
                if (fiduciaryIdStr == null) {
                    OutputProcessor.errorResponse(res, 400, "Bad Request", "Missing fiduciary_id.", req.getRequestURI());
                    return;
                }
                String name = getFiduciaryName(fiduciaryIdStr);
                JSONObject nameRes = new JSONObject();
                nameRes.put("success", true);
                nameRes.put("fiduciary_name", name);
                OutputProcessor.send(res, 200, nameRes);
                return;
            }

            // Security Check for protected lifecycle commands
            if (syncToken == null) {
                OutputProcessor.errorResponse(res, 400, "Bad Request", "Missing sync_token.", req.getRequestURI());
                return;
            }

            // userId and fiduciaryId are extracted from the signed token — request body values are not trusted
            PrincipalContext ctx = validateSyncToken(syncToken);
            if (ctx == null) {
                OutputProcessor.errorResponse(res, 401, "Unauthorized", "Invalid or expired Sync Token.", req.getRequestURI());
                return;
            }

            JSONObject result = new JSONObject();
            switch (command.toUpperCase()) {
                case "GET_CONSENT_DETAILS":
                    result = handleGetConsentDetails(ctx);
                    break;
                case "REVOKE_PURPOSE":
                    String purposeId = (String) input.get("purpose_id");
                    if (purposeId == null || purposeId.trim().isEmpty()) {
                        OutputProcessor.errorResponse(res, 400, "Bad Request", "Missing purpose_id.", req.getRequestURI());
                        return;
                    }
                    result = handleRevokePurpose(ctx, purposeId);
                    break;
                case "GLOBAL_ERASURE":
                    result = handleGlobalErasure(ctx);
                    break;
                default:
                    OutputProcessor.errorResponse(res, 400, "Bad Request", "Unsupported wallet command.", req.getRequestURI());
                    return;
            }

            OutputProcessor.send(res, 200, result);

        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, 500, "Internal Error", e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * Retrieves the latest active consent record for the authenticated principal.
     */
    private JSONObject handleGetConsentDetails(PrincipalContext ctx) throws Exception {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        String sql = "SELECT data_point_consents, policy_id, policy_version, timestamp FROM consent_records " +
                "WHERE user_id = ? AND fiduciary_id::text = ? AND is_active_consent = TRUE LIMIT 1";

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, ctx.userId);
            pstmt.setString(2, ctx.fiduciaryId);
            rs = pstmt.executeQuery();

            JSONObject res = new JSONObject();
            if (rs.next()) {
                res.put("success", true);
                res.put("policy_id", rs.getString("policy_id"));
                res.put("policy_version", rs.getString("policy_version"));
                res.put("timestamp", rs.getTimestamp("timestamp").toString());
                res.put("data_point_consents", new JSONParser().parse(rs.getString("data_point_consents")));
            } else {
                res.put("success", false);
                res.put("message", "No active consent records found in registry.");
            }
            return res;
        } catch (SQLException e) {
            System.err.println("SQL Error in handleGetConsentDetails: " + e.getMessage());
            throw e;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private String getFiduciaryName(String fiduciaryIdStr) throws SQLException {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sql = "SELECT name FROM fiduciaries WHERE id::text = ? OR name = ?";
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, fiduciaryIdStr);
            pstmt.setString(2, fiduciaryIdStr);
            rs = pstmt.executeQuery();
            if (rs.next()) return rs.getString("name");
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return fiduciaryIdStr;
    }

    private JSONObject handleRevokePurpose(PrincipalContext ctx, String purposeId) throws Exception {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();

        String selectSql = "SELECT id, policy_id, policy_version, data_point_consents FROM consent_records " +
                "WHERE user_id = ? AND fiduciary_id::text = ? AND is_active_consent = TRUE LIMIT 1";

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);

            pstmt = conn.prepareStatement(selectSql);
            pstmt.setString(1, ctx.userId);
            pstmt.setString(2, ctx.fiduciaryId);
            rs = pstmt.executeQuery();

            if (!rs.next()) throw new Exception("No active record found to revoke.");

            String oldId = rs.getString("id");
            String pId = rs.getString("policy_id");
            String pVer = rs.getString("policy_version");
            JSONArray consents = (JSONArray) new JSONParser().parse(rs.getString("data_point_consents"));

            for (Object obj : consents) {
                JSONObject item = (JSONObject) obj;
                if (purposeId.equals(item.get("data_point_id"))) {
                    item.put("consent_granted", false);
                    item.put("timestamp_updated", Instant.now().toString());
                }
            }

            String dSql = "UPDATE consent_records SET is_active_consent = FALSE, last_updated_at = NOW() WHERE id = ?";
            try (PreparedStatement dStmt = conn.prepareStatement(dSql)) {
                dStmt.setObject(1, UUID.fromString(oldId));
                dStmt.executeUpdate();
            }

            String iSql = "INSERT INTO consent_records (id, user_id, fiduciary_id, policy_id, policy_version, timestamp, jurisdiction, consent_status_general, consent_mechanism, data_point_consents, is_active_consent, created_at, language_selected, ip_address) VALUES (uuid_generate_v4(), ?, ?, ?, ?, NOW(), 'IN', 'WITHDRAWN', 'WALLET_REVOKE', ?::jsonb, TRUE, NOW(), 'en', '0.0.0.0')";
            try (PreparedStatement iStmt = conn.prepareStatement(iSql)) {
                iStmt.setString(1, ctx.userId);
                try { iStmt.setObject(2, UUID.fromString(ctx.fiduciaryId)); } catch (Exception ex) { iStmt.setString(2, ctx.fiduciaryId); }
                iStmt.setString(3, pId);
                iStmt.setString(4, pVer);
                iStmt.setString(5, consents.toJSONString());
                iStmt.executeUpdate();
            }

            // Flag this principal for CES re-evaluation so the background purge job
            // creates the purge_requests for the now-withdrawn purpose. Mirrors the
            // canonical withdraw path in Consent (resets last_ces_run to NULL).
            flagCESForPurge(conn, ctx.userId, ctx.fiduciaryId, "WALLET_REVOKE");

            conn.commit();
            JSONObject res = new JSONObject();
            res.put("success", true);
            res.put("message", "Revoked and new artifact recorded.");
            return res;
        } catch (Exception e) {
            if (conn != null) conn.rollback();
            throw e;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private JSONObject handleGlobalErasure(PrincipalContext ctx) throws Exception {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        String sSql = "SELECT id, policy_id, policy_version, data_point_consents FROM consent_records WHERE user_id = ? AND fiduciary_id::text = ? AND is_active_consent = TRUE LIMIT 1";

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);
            pstmt = conn.prepareStatement(sSql);
            pstmt.setString(1, ctx.userId);
            pstmt.setString(2, ctx.fiduciaryId);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                String oldId = rs.getString("id");
                String pId = rs.getString("policy_id");
                String pVer = rs.getString("policy_version");
                JSONArray consents = (JSONArray) new JSONParser().parse(rs.getString("data_point_consents"));

                for (Object obj : consents) {
                    JSONObject item = (JSONObject) obj;
                    item.put("consent_granted", false);
                    item.put("timestamp_updated", Instant.now().toString());
                }

                String dSql = "UPDATE consent_records SET is_active_consent = FALSE, last_updated_at = NOW() WHERE id = ?";
                try (PreparedStatement dStmt = conn.prepareStatement(dSql)) {
                    dStmt.setObject(1, UUID.fromString(oldId));
                    dStmt.executeUpdate();
                }

                String iSql = "INSERT INTO consent_records (id, user_id, fiduciary_id, policy_id, policy_version, timestamp, jurisdiction, consent_status_general, consent_mechanism, data_point_consents, is_active_consent, created_at, language_selected, ip_address) VALUES (uuid_generate_v4(), ?, ?, ?, ?, NOW(), 'IN', 'ERASURE_REQUEST', 'ERASURE_REQUEST', ?::jsonb, FALSE, NOW(), 'en', '0.0.0.0')";
                try (PreparedStatement iStmt = conn.prepareStatement(iSql)) {
                    iStmt.setString(1, ctx.userId);
                    try { iStmt.setObject(2, UUID.fromString(ctx.fiduciaryId)); } catch (Exception ex) { iStmt.setString(2, ctx.fiduciaryId); }
                    iStmt.setString(3, pId);
                    iStmt.setString(4, pVer);
                    iStmt.setString(5, consents.toJSONString());
                    iStmt.executeUpdate();
                }

                // Flag this principal for CES re-evaluation so the background purge job
                // picks up the ERASURE_REQUEST and creates the purge_requests. Mirrors the
                // canonical erasure path in Consent (resets last_ces_run to NULL). The
                // DPO-driven purge flow itself is owned by Compliance/CES — we only
                // create the request by flagging the principal.
                flagCESForPurge(conn, ctx.userId, ctx.fiduciaryId, "ERASURE_REQUEST");
            }
            conn.commit();
            JSONObject res = new JSONObject();
            res.put("success", true);
            res.put("message", "Global erasure request recorded.");
            return res;
        } catch (Exception e) {
            if (conn != null) conn.rollback();
            throw e;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    /**
     * Registers/refreshes this principal in data_principal and resets last_ces_run to NULL,
     * which is what makes the CES batch job re-evaluate the latest consent action and create
     * the downstream purge_requests. This is the same mechanism the canonical withdraw/erasure
     * path in Consent uses to trigger purges; runs inside the caller's transaction so the
     * record write and the CES flag commit (or roll back) atomically.
     */
    private void flagCESForPurge(Connection conn, String userId, String fiduciaryId, String lastConsentMechanism) throws SQLException {
        String sql = "INSERT INTO data_principal (user_id, fiduciary_id, last_consent_mechanism, last_ces_run) " +
                "VALUES (?, ?, ?, NULL) " +
                "ON CONFLICT (user_id, fiduciary_id) DO UPDATE SET " +
                "last_consent_mechanism = EXCLUDED.last_consent_mechanism, last_ces_run = NULL";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, userId);
            try { stmt.setObject(2, UUID.fromString(fiduciaryId)); } catch (Exception ex) { stmt.setString(2, fiduciaryId); }
            stmt.setString(3, lastConsentMechanism);
            stmt.executeUpdate();
        }
    }

    /**
     * Validates the wallet sync token (a signed JWT with type=SYNC).
     * userId and fiduciaryId are extracted from the token claims — the request body is not trusted.
     */
    private PrincipalContext validateSyncToken(String token) {
        Claims claims = JWTUtil.getSyncClaimsFromToken(token);
        if (claims == null) return null;
        String tokenUserId = claims.getSubject();
        String tokenFiduciaryId = (String) claims.get("fid");
        if (tokenUserId == null || tokenFiduciaryId == null) return null;
        return new PrincipalContext(tokenUserId, tokenFiduciaryId);
    }

    private static class PrincipalContext {
        String userId; String fiduciaryId;
        PrincipalContext(String u, String f) { this.userId = u; this.fiduciaryId = f; }
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return "POST".equalsIgnoreCase(method);
    }
}