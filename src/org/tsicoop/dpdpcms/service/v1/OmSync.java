package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Set;
import java.util.UUID;

/**
 * OmSync — the CMS landing surface for the bidirectional OM<->CMS sync (vAIb-a0a0).
 *
 * <p>Direction 1 (OM -> CMS PUSH): the native OpenMetadata DPDPA DPIA app assesses a whole
 * customer across EVERY connector-fed integration under the customer's OM Domain
 * (wix-&lt;instanceId&gt;) and PUSHES the combined cross-source DPIA verdict here via
 * {@code receive_om_assessment}. This is a DIFFERENT, complementary view to the CMS's OWN
 * native RoPA DPIA ({@link Dpia}); dpia.html renders BOTH ("show both"). The OM verdict is
 * cached (append-only, latest-wins) in {@code om_assessments}.
 *
 * <p>Direction 2 read-back is served by {@code get_om_assessment}: the DPO console reads this
 * tenant's LATEST OM-pushed verdict for the "OpenMetadata cross-source assessment" panel.
 *
 * <p><b>Auth + tenant isolation (vAIb-ae11 / vAIb-a0a0) — the two callers use two seams:</b>
 * <ul>
 *   <li>{@code receive_om_assessment} is called SERVER-TO-SERVER by the OM app with an
 *       API KEY/SECRET (X-API-Key / X-API-Secret). The tenant is SERVER-DERIVED from the
 *       key via {@link Fiduciary#getFiduciaryId} — NEVER trusted from the body. Any body
 *       {@code fiduciary_id} that disagrees with the authenticated key's tenant is a 403.
 *       So one OM app key can only ever write ITS OWN tenant's OM assessment — a push can
 *       never write another tenant's row. (This func is whitelisted in the CLIENT branch of
 *       {@code InterceptingFilter} + gated on the WRITE scope, exactly like {@code Consent}.)
 *   <li>{@code get_om_assessment} is called by the DPO console (operator session Bearer JWT)
 *       via {@code /api/v1/admin/omsync}; the tenant is SERVER-DERIVED via
 *       {@link InputProcessor#resolveTenantScope} — a DPO for tenant A can never read
 *       tenant B's OM assessment.
 * </ul>
 *
 * <p><b>No raw PII</b>: the stored verdict is value-free / metadata-only — status enum,
 * integer score, markdown summary, gap CODES + counts, and a per-integration roll-up
 * (counts/statuses). A defensive value-free guard rejects any payload that smells of raw PII
 * (an '@' in the summary/gaps/per-integration blobs), mirroring {@code CoverageAuditResult}.
 * All stored text is HTML-escaped before persistence (defence-in-depth against a compromised
 * pushing app), then re-escaped on render by the console.
 */
public class OmSync implements Action {

    // Allowed combined statuses from the OM engine (worst-wins roll-up). Anything else -> 400.
    private static final Set<String> ALLOWED_STATUS =
            Set.of("compliant", "attention", "non_compliant", "unknown");

    private static final int MAX_SUMMARY_LEN = 20000;   // generous but bounded
    private static final int MAX_DOMAIN_LEN  = 256;

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        try {
            req.setCharacterEncoding("UTF-8");
            JSONObject input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing '_func'.", req.getRequestURI());
                return;
            }

            switch (func.toLowerCase()) {
                case "receive_om_assessment": handleReceive(input, req, res); break;
                case "get_om_assessment":     handleGet(input, req, res);     break;
                case "get_cms_compliance_counts": handleGetComplianceCounts(input, req, res); break;
                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Unknown '_func': " + func, req.getRequestURI());
            }
        } catch (SQLException e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", e.getMessage(), req.getRequestURI());
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage(), req.getRequestURI());
        }
    }

    // ── Direction 1: OM -> CMS push receiver (api-key server-to-server) ──────────────

    /**
     * Land the OM-pushed combined DPIA verdict for the CALLER'S OWN tenant.
     *
     * <p>Body: {@code { _func, fiduciary_id?, om_domain, dpia_status, dpia_score,
     * dpia_summary, dpia_gaps, per_integration, assessed_at }}. The AUTHORITATIVE tenant is
     * the OM app's api-key (server-derived) — {@code fiduciary_id} in the body is validated to
     * MATCH the authenticated key's tenant, never trusted as authority (a mismatch is a 403).
     */
    private void handleReceive(JSONObject input, HttpServletRequest req, HttpServletResponse res) throws SQLException {
        // ── AUTH: the pushing OM app authenticates with an api-key/secret. Derive the tenant
        // SERVER-SIDE from the key (mirrors Consent.java's api-key seam). NEVER the body value.
        String apiKey = req.getHeader("X-API-Key");
        String apiSecret = req.getHeader("X-API-Secret");
        if (apiKey == null || apiKey.isEmpty() || apiSecret == null || apiSecret.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized",
                    "receive_om_assessment requires an API key/secret (server-to-server).", req.getRequestURI());
            return;
        }
        String fiduciaryIdStr;
        try {
            fiduciaryIdStr = new Fiduciary().getFiduciaryId(UUID.fromString(apiKey), apiSecret);
        } catch (IllegalArgumentException badKey) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid API key.", req.getRequestURI());
            return;
        }
        if (fiduciaryIdStr == null || fiduciaryIdStr.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized",
                    "Unable to resolve authenticated fiduciary from API key.", req.getRequestURI());
            return;
        }
        UUID fiduciaryId;
        try {
            fiduciaryId = UUID.fromString(fiduciaryIdStr);
        } catch (IllegalArgumentException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Resolved fiduciary is not a valid id.", req.getRequestURI());
            return;
        }

        // Cross-tenant guard: reject a body fiduciary_id that names a DIFFERENT tenant than the
        // authenticated key. The OM app SHOULD send its own; a mismatch means a misconfigured or
        // hostile caller trying to write another tenant's row -> 403 (fail closed). (vAIb-ae11.)
        String bodyFidStr = (String) input.get("fiduciary_id");
        if (bodyFidStr != null && !bodyFidStr.isEmpty() && !bodyFidStr.equalsIgnoreCase(fiduciaryIdStr)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden",
                    "Body 'fiduciary_id' does not match the authenticated fiduciary (cross-tenant push denied).",
                    req.getRequestURI());
            return;
        }

        // ── Validate + sanitise the payload (value-free / metadata-only). ──────────────
        String omDomain = clip(str(input.get("om_domain")), MAX_DOMAIN_LEN);
        if (omDomain.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "'om_domain' is required.", req.getRequestURI());
            return;
        }
        String status = str(input.get("dpia_status")).trim().toLowerCase();
        if (!ALLOWED_STATUS.contains(status)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                    "'dpia_status' must be one of compliant/attention/non_compliant/unknown.", req.getRequestURI());
            return;
        }
        int score = asInt(input.get("dpia_score"));
        if (score < 0) score = 0;
        if (score > 100) score = 100;

        // dpia_summary: markdown text -> HTML-escape before storage (defence in depth against a
        // compromised pushing app; the console re-escapes on render). NO PII by contract.
        String summary = clip(str(input.get("dpia_summary")), MAX_SUMMARY_LEN);

        // dpia_gaps + per_integration arrive as JSON (object/array). Serialise to canonical JSON
        // strings for ?::jsonb storage; default to empty container when absent/malformed.
        String gapsJson = toJsonText(input.get("dpia_gaps"), "{}");
        String perIntegrationJson = toJsonText(input.get("per_integration"), "[]");

        // Value-free guard (mirrors CoverageAuditResult): the OM verdict is metadata-only by
        // contract. An '@' in any free-text blob suggests a raw email value leaked in -> hard 400.
        // The legitimate OM app never sends principal PII, so this is a no-op for it.
        if (summary.indexOf('@') >= 0 || gapsJson.indexOf('@') >= 0 || perIntegrationJson.indexOf('@') >= 0) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                    "OM assessment must be value-free (no PII values); received an '@' (email-like value).",
                    req.getRequestURI());
            return;
        }

        // HTML-escape the stored free text (defence in depth). The OM engine emits markdown, not
        // HTML, so escaping is safe and reversible enough for the console (which renders as text).
        String safeDomain = htmlEscape(omDomain, MAX_DOMAIN_LEN);
        String safeSummary = summary.isEmpty() ? null : htmlEscape(summary, MAX_SUMMARY_LEN);

        // assessed_at: OM-supplied ISO-8601 timestamp; null -> DB default now().
        String assessedAt = clip(str(input.get("assessed_at")), 64);

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            String sql = "INSERT INTO om_assessments "
                    + "(fiduciary_id, om_domain, dpia_status, dpia_score, dpia_summary, dpia_gaps, per_integration, assessed_at) "
                    + "VALUES (?, ?, ?, ?, ?, ?::jsonb, ?::jsonb, COALESCE(?::timestamptz, now())) "
                    + "RETURNING id, assessed_at, created_at";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            pstmt.setString(2, safeDomain);
            pstmt.setString(3, status);
            pstmt.setInt(4, score);
            pstmt.setString(5, safeSummary);
            pstmt.setString(6, gapsJson);
            pstmt.setString(7, perIntegrationJson);
            pstmt.setString(8, (assessedAt == null || assessedAt.isEmpty()) ? null : assessedAt);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject out = new JSONObject();
                out.put("success", true);
                out.put("id", rs.getObject("id").toString());
                out.put("assessed_at", rs.getTimestamp("assessed_at").toInstant().toString());
                out.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                OutputProcessor.send(res, HttpServletResponse.SC_OK, out);
            } else {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Error", "INSERT returned no row.", req.getRequestURI());
            }
        } catch (SQLException e) {
            // A bad assessed_at cast or bad jsonb is a client error, not a server fault.
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Could not store OM assessment: " + e.getMessage(), req.getRequestURI());
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    // ── Direction 2 read-back: latest OM assessment for the DPO console (operator JWT) ──

    /**
     * Return this tenant's LATEST OM-pushed cross-source DPIA verdict for the console panel.
     *
     * <p>Tenant is SERVER-DERIVED via {@link InputProcessor#resolveTenantScope} (operator
     * session); a DPO for tenant A can never read tenant B's OM assessment. Returns
     * {@code {found:false}} when no OM assessment has been pushed yet.
     */
    private void handleGet(JSONObject input, HttpServletRequest req, HttpServletResponse res) throws SQLException {
        // Operator-console read: hard-scoped to the operator's own tenant. false == a tenant
        // operator need not name a target (matches CoverageAuditResult / the DPO console seam).
        UUID fiduciaryId = InputProcessor.resolveTenantScope(req, res, false);
        if (fiduciaryId == null) return;   // error already sent (401/403)

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            String sql = "SELECT om_domain, dpia_status, dpia_score, dpia_summary, dpia_gaps, per_integration, assessed_at, created_at "
                    + "FROM om_assessments WHERE fiduciary_id = ? "
                    + "ORDER BY assessed_at DESC, created_at DESC LIMIT 1";
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject out = new JSONObject();
                out.put("found", true);
                out.put("om_domain", rs.getString("om_domain"));
                out.put("dpia_status", rs.getString("dpia_status"));
                out.put("dpia_score", rs.getInt("dpia_score"));
                out.put("dpia_summary", rs.getString("dpia_summary"));
                out.put("dpia_gaps", parseJson(rs.getString("dpia_gaps")));
                out.put("per_integration", parseJson(rs.getString("per_integration")));
                out.put("assessed_at", rs.getTimestamp("assessed_at").toInstant().toString());
                out.put("created_at", rs.getTimestamp("created_at").toInstant().toString());
                OutputProcessor.send(res, HttpServletResponse.SC_OK, out);
            } else {
                JSONObject out = new JSONObject();
                out.put("found", false);
                OutputProcessor.send(res, HttpServletResponse.SC_OK, out);
            }
        } catch (SQLException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database Error", e.getMessage(), req.getRequestURI());
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    // ── Direction 2: CMS -> OM pull source (api-key server-to-server, value-free counts) ──

    /**
     * Return this tenant's VALUE-FREE compliance counts for the OM->OM reflection (Direction 2:
     * the OM app pulls these and mirrors them onto the OM catalog). Counts/statuses ONLY — active
     * RoPA count, active policy count, genuine consent-record count, grievance count. NO principal
     * PII, NO RoPA rows, NO consent values ever leave the CMS through this seam.
     *
     * <p>AUTH is the SAME api-key server-to-server seam as {@code receive_om_assessment}: the tenant
     * is SERVER-DERIVED from the api-key ({@link Fiduciary#getFiduciaryId}), never a body value; a
     * body {@code fiduciary_id} that disagrees is a 403. So the OM app can only ever read ITS OWN
     * tenant's counts. (READ scope; whitelisted in the CLIENT branch of {@code InterceptingFilter}.)
     */
    private void handleGetComplianceCounts(JSONObject input, HttpServletRequest req, HttpServletResponse res) throws SQLException {
        String apiKey = req.getHeader("X-API-Key");
        String apiSecret = req.getHeader("X-API-Secret");
        if (apiKey == null || apiKey.isEmpty() || apiSecret == null || apiSecret.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized",
                    "get_cms_compliance_counts requires an API key/secret (server-to-server).", req.getRequestURI());
            return;
        }
        String fiduciaryIdStr;
        try {
            fiduciaryIdStr = new Fiduciary().getFiduciaryId(UUID.fromString(apiKey), apiSecret);
        } catch (IllegalArgumentException badKey) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid API key.", req.getRequestURI());
            return;
        }
        if (fiduciaryIdStr == null || fiduciaryIdStr.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized",
                    "Unable to resolve authenticated fiduciary from API key.", req.getRequestURI());
            return;
        }
        String bodyFidStr = (String) input.get("fiduciary_id");
        if (bodyFidStr != null && !bodyFidStr.isEmpty() && !bodyFidStr.equalsIgnoreCase(fiduciaryIdStr)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden",
                    "Body 'fiduciary_id' does not match the authenticated fiduciary (cross-tenant read denied).",
                    req.getRequestURI());
            return;
        }
        UUID fiduciaryId;
        try { fiduciaryId = UUID.fromString(fiduciaryIdStr); }
        catch (IllegalArgumentException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Resolved fiduciary is not a valid id.", req.getRequestURI());
            return;
        }

        // Value-free counts, each fiduciary-scoped. COUNT(*) only — no row content leaves the CMS.
        long ropaCount = countScalar("SELECT COUNT(*) FROM ropa_entries WHERE fiduciary_id = ? AND status = 'active'", fiduciaryId);
        long policyCount = countScalar("SELECT COUNT(*) FROM consent_policies WHERE fiduciary_id = ? AND status = 'ACTIVE'", fiduciaryId);
        long consentCount = countScalar("SELECT COUNT(*) FROM consent_records WHERE fiduciary_id = ?", fiduciaryId);
        long grievanceCount = countScalar("SELECT COUNT(*) FROM grievances WHERE fiduciary_id = ?", fiduciaryId);

        JSONObject out = new JSONObject();
        out.put("found", true);
        out.put("cms_ropa_count", ropaCount);
        out.put("cms_active_policies", policyCount);
        out.put("cms_consent_count", consentCount);
        out.put("cms_grievance_count", grievanceCount);
        OutputProcessor.send(res, HttpServletResponse.SC_OK, out);
    }

    /** Fiduciary-scoped COUNT(*) helper. Returns 0 on any error (fail-soft; a count is non-critical). */
    private long countScalar(String sql, UUID fiduciaryId) {
        PoolDB pool = null;
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            pool = new PoolDB();
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            rs = pstmt.executeQuery();
            return rs.next() ? rs.getLong(1) : 0L;
        } catch (Exception e) {
            System.err.println("[OmSync] count failed (fail-soft): " + e.getMessage());
            return 0L;
        } finally {
            if (pool != null) try { pool.cleanup(rs, pstmt, conn); } catch (Exception ignored) {}
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────────────────

    private String str(Object v) { return v == null ? "" : String.valueOf(v); }

    /**
     * HTML-escape free text at the storage boundary so no raw markup is ever persisted
     * (defence-in-depth vs stored XSS if a compromised OM app were to push markup that a
     * console later renders). Mirrors Fiduciary.htmlEscape/RopaDeriver.escape. Null-safe; caps length.
     */
    private static String htmlEscape(String s, int maxLen) {
        if (s == null) return null;
        String t = s.length() > maxLen ? s.substring(0, maxLen) : s;
        return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    private String clip(String v, int limit) {
        if (v == null) return "";
        return v.length() > limit ? v.substring(0, limit) : v;
    }

    private int asInt(Object o) {
        if (o instanceof Number) return ((Number) o).intValue();
        if (o instanceof String) {
            try { return (int) Double.parseDouble((String) o); } catch (Exception ignore) { return 0; }
        }
        return 0;
    }

    /**
     * Serialise a body value (JSONObject / JSONArray already parsed by InputProcessor, or a
     * JSON string) into a canonical JSON text for ?::jsonb storage. Malformed / absent -> the
     * given default container. Defensive: a malformed blob never crashes the push.
     */
    private String toJsonText(Object v, String defaultContainer) {
        if (v == null) return defaultContainer;
        if (v instanceof JSONObject || v instanceof JSONArray) return v.toString();
        String s = String.valueOf(v).trim();
        if (s.isEmpty()) return defaultContainer;
        try {
            Object parsed = new JSONParser().parse(s);
            if (parsed instanceof JSONObject || parsed instanceof JSONArray) return parsed.toString();
        } catch (ParseException ignore) { /* fall through */ }
        return defaultContainer;
    }

    /** Parse a stored JSONB text back into a JSON object/array for the response; raw on failure. */
    private Object parseJson(String s) {
        if (s == null || s.isEmpty()) return null;
        try { return new JSONParser().parse(s); }
        catch (ParseException e) { return s; }
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        // Per-func auth is enforced in post() (api-key for receive, operator JWT for get). The
        // filter already ran InputProcessor.validate (jschema) for the CLIENT/ADMIN branches;
        // this mirrors Dpia.validate — method + basic content-type/body validation.
        return "POST".equalsIgnoreCase(method) && InputProcessor.validate(req, res);
    }
}
