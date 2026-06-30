package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;

/**
 * Service to persist and retrieve the Coverage Audit result so the DPDPA.center
 * My-Data page can show the last result instantly instead of re-running a full
 * live Wix scan on every page load.
 *
 * Two functions:
 *   record_coverage_audit — INSERT a new audit result row for the caller's tenant.
 *   get_coverage_audit    — SELECT the latest audit result row for the caller's tenant.
 *
 * NO PII is ever stored: only per-source covered/derived/orphan integer counts
 * (the value-free coverage summary shape). fiduciary_id is ALWAYS server-derived
 * (resolveTenantScope); the body value is never trusted.
 */
public class CoverageAuditResult implements Action {

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        try {
            JSONObject input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null) {
                OutputProcessor.errorResponse(res, 400, "Bad Request", "Missing _func.", req.getRequestURI());
                return;
            }

            switch (func.toLowerCase()) {
                case "record_coverage_audit":
                    handleRecord(input, req, res);
                    break;
                case "get_coverage_audit":
                    handleGet(input, req, res);
                    break;
                default:
                    OutputProcessor.errorResponse(res, 400, "Bad Request", "Unknown function.", req.getRequestURI());
            }
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, 500, "Internal Error", e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * INSERT a new coverage audit result row.
     *
     * Body: { _func, summary (object), covered_total (number), derived_total (number), orphan_total (number) }
     * fiduciary_id is resolved server-side only — the body value is never read.
     */
    private void handleRecord(JSONObject input, HttpServletRequest req, HttpServletResponse res) throws SQLException {
        // vAIb (mydata-ui): resolveTenantScope with false — a tenant operator does NOT
        // need to name a target; they are hard-scoped to their own fiduciary. false
        // prevents the 403 that 'true' would emit when no body fiduciary_id is present.
        UUID fiduciaryId = InputProcessor.resolveTenantScope(req, res, false);
        if (fiduciaryId == null) return;

        // Extract fields from the body. summary is required; totals default to 0.
        Object summaryObj = input.get("summary");
        if (summaryObj == null) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "summary is required.", req.getRequestURI());
            return;
        }
        // Serialise to JSON string for ?::jsonb storage. The value is a JSONObject
        // already parsed from the request body by InputProcessor.
        String summaryJson = summaryObj.toString();
        // Defence in depth (security review follow-up): the summary is value-free by
        // contract (per-source covered/derived/orphan counts, never PII values). Do
        // not depend solely on the caller — reject a summary that smells of raw PII
        // (an '@' suggests an email value leaked into the snapshot). The legitimate
        // fabric caller never sends values, so this is a no-op for it and a hard stop
        // for a buggy/compromised caller.
        if (summaryJson.indexOf('@') >= 0) {
            OutputProcessor.errorResponse(res, 400, "Bad Request",
                    "summary must be value-free (no PII values); received an '@' (email-like value).",
                    req.getRequestURI());
            return;
        }

        int coveredTotal = 0;
        Object ct = input.get("covered_total");
        if (ct instanceof Long) coveredTotal = ((Long) ct).intValue();

        int derivedTotal = 0;
        Object dt = input.get("derived_total");
        if (dt instanceof Long) derivedTotal = ((Long) dt).intValue();

        int orphanTotal = 0;
        Object ot = input.get("orphan_total");
        if (ot instanceof Long) orphanTotal = ((Long) ot).intValue();

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();

            String sql = "INSERT INTO coverage_audit_results "
                    + "(fiduciary_id, summary, covered_total, derived_total, orphan_total) "
                    + "VALUES (?, ?::jsonb, ?, ?, ?) "
                    + "RETURNING id, scanned_at";

            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            pstmt.setString(2, summaryJson);
            pstmt.setInt(3, coveredTotal);
            pstmt.setInt(4, derivedTotal);
            pstmt.setInt(5, orphanTotal);

            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject output = new JSONObject();
                output.put("success", true);
                output.put("id", rs.getObject("id").toString());
                output.put("scanned_at", rs.getTimestamp("scanned_at").toInstant().toString());
                OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
            } else {
                OutputProcessor.errorResponse(res, 500, "Internal Error", "INSERT returned no row.", req.getRequestURI());
            }
        } catch (SQLException e) {
            OutputProcessor.errorResponse(res, 500, "Database Error", e.getMessage(), req.getRequestURI());
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    /**
     * SELECT the latest coverage audit result for the caller's tenant.
     *
     * Returns {found:true, summary, covered_total, derived_total, orphan_total, scanned_at}
     * or     {found:false} when no audit result has been recorded yet.
     */
    private void handleGet(JSONObject input, HttpServletRequest req, HttpServletResponse res) throws SQLException {
        // vAIb (mydata-ui): resolveTenantScope with false — same reasoning as handleRecord.
        UUID fiduciaryId = InputProcessor.resolveTenantScope(req, res, false);
        if (fiduciaryId == null) return;

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();

            String sql = "SELECT summary, covered_total, derived_total, orphan_total, scanned_at "
                    + "FROM coverage_audit_results "
                    + "WHERE fiduciary_id = ? "
                    + "ORDER BY scanned_at DESC LIMIT 1";

            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                JSONObject output = new JSONObject();
                output.put("found", true);
                output.put("covered_total", rs.getInt("covered_total"));
                output.put("derived_total", rs.getInt("derived_total"));
                output.put("orphan_total", rs.getInt("orphan_total"));
                output.put("scanned_at", rs.getTimestamp("scanned_at").toInstant().toString());

                // Parse JSONB string back into a JSON object before sending.
                String summaryStr = rs.getString("summary");
                try {
                    output.put("summary", new JSONParser().parse(summaryStr));
                } catch (ParseException pe) {
                    output.put("summary", summaryStr); // fallback: raw string
                }

                OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
            } else {
                JSONObject output = new JSONObject();
                output.put("found", false);
                OutputProcessor.send(res, HttpServletResponse.SC_OK, output);
            }
        } catch (SQLException e) {
            OutputProcessor.errorResponse(res, 500, "Database Error", e.getMessage(), req.getRequestURI());
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return "POST".equalsIgnoreCase(method) && InputProcessor.processAdminHeader(req, res);
    }
}
