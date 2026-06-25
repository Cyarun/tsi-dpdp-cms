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
 * Service to persist and retrieve the onboarding discovery footprint as a
 * tenant baseline. RoPA + Compliance can later reconcile actual coverage
 * against this snapshot.
 *
 * Two functions:
 *   record_discovery_baseline — INSERT a new baseline row for the caller's tenant.
 *   get_discovery_baseline    — SELECT the latest baseline row for the caller's tenant.
 *
 * NO PII is ever stored: only category/source/activity metadata + counts
 * (the value-free NormalizedInventory shape). fiduciary_id is ALWAYS
 * server-derived (resolveTenantScope); the body value is never trusted.
 */
public class DiscoveryBaseline implements Action {

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
                case "record_discovery_baseline":
                    handleRecord(input, req, res);
                    break;
                case "get_discovery_baseline":
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
     * INSERT a new discovery baseline row.
     *
     * Body: { _func, inventory (object), activity_count (number), source_breakdown (object) }
     * fiduciary_id is resolved server-side only — the body value is never read.
     */
    private void handleRecord(JSONObject input, HttpServletRequest req, HttpServletResponse res) throws SQLException {
        // vAIb (U3): resolveTenantScope with false — a tenant operator does NOT need
        // to name a target; they are hard-scoped to their own fiduciary. false prevents
        // the 403 that 'true' would emit when no body fiduciary_id is present.
        UUID fiduciaryId = InputProcessor.resolveTenantScope(req, res, false);
        if (fiduciaryId == null) return;

        // Extract fields from the body. inventory is required; the others have defaults.
        Object inventoryObj = input.get("inventory");
        if (inventoryObj == null) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "inventory is required.", req.getRequestURI());
            return;
        }
        // Serialise to JSON string for ?::jsonb storage. The value is a JSONObject
        // already parsed from the request body by InputProcessor.
        String inventoryJson = inventoryObj.toString();
        // Defence in depth (security review follow-up): the baseline is value-free by
        // contract (category/source/activity METADATA + counts, never PII values). Do
        // not depend solely on the caller — reject an inventory that smells of raw PII
        // (an '@' suggests an email value leaked into the snapshot). The legitimate
        // fabric caller never sends values, so this is a no-op for it and a hard stop
        // for a buggy/compromised caller.
        if (inventoryJson.indexOf('@') >= 0) {
            OutputProcessor.errorResponse(res, 400, "Bad Request",
                    "inventory must be value-free (no PII values); received an '@' (email-like value).",
                    req.getRequestURI());
            return;
        }

        int activityCount = 0;
        Object ac = input.get("activity_count");
        if (ac instanceof Long) activityCount = ((Long) ac).intValue();

        String sourceBreakdownJson = null;
        Object sb = input.get("source_breakdown");
        if (sb != null) sourceBreakdownJson = sb.toString();

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();

            String sql = "INSERT INTO discovery_baseline "
                    + "(fiduciary_id, inventory, activity_count, source_breakdown) "
                    + "VALUES (?, ?::jsonb, ?, ?::jsonb) "
                    + "RETURNING id, captured_at";

            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            pstmt.setString(2, inventoryJson);
            pstmt.setInt(3, activityCount);
            pstmt.setString(4, sourceBreakdownJson); // null is fine — column is nullable

            rs = pstmt.executeQuery();
            if (rs.next()) {
                JSONObject output = new JSONObject();
                output.put("success", true);
                output.put("id", rs.getObject("id").toString());
                output.put("captured_at", rs.getTimestamp("captured_at").toInstant().toString());
                OutputProcessor.send(res, 200, output);
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
     * SELECT the latest discovery baseline for the caller's tenant.
     *
     * Returns {found:true, inventory, activity_count, source_breakdown, captured_at}
     * or     {found:false} when no baseline has been recorded yet.
     */
    private void handleGet(JSONObject input, HttpServletRequest req, HttpServletResponse res) throws SQLException {
        // vAIb (U3): resolveTenantScope with false — same reasoning as handleRecord.
        UUID fiduciaryId = InputProcessor.resolveTenantScope(req, res, false);
        if (fiduciaryId == null) return;

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();

            String sql = "SELECT inventory, activity_count, source_breakdown, captured_at "
                    + "FROM discovery_baseline "
                    + "WHERE fiduciary_id = ? "
                    + "ORDER BY captured_at DESC LIMIT 1";

            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                JSONObject output = new JSONObject();
                output.put("found", true);
                output.put("activity_count", rs.getInt("activity_count"));
                output.put("captured_at", rs.getTimestamp("captured_at").toInstant().toString());

                // Parse JSONB strings back into JSON objects before sending.
                String inventoryStr = rs.getString("inventory");
                try {
                    output.put("inventory", new JSONParser().parse(inventoryStr));
                } catch (ParseException pe) {
                    output.put("inventory", inventoryStr); // fallback: raw string
                }

                String sbStr = rs.getString("source_breakdown");
                if (sbStr != null) {
                    try {
                        output.put("source_breakdown", new JSONParser().parse(sbStr));
                    } catch (ParseException pe) {
                        output.put("source_breakdown", sbStr);
                    }
                } else {
                    output.put("source_breakdown", null);
                }

                OutputProcessor.send(res, 200, output);
            } else {
                JSONObject output = new JSONObject();
                output.put("found", false);
                OutputProcessor.send(res, 200, output);
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
