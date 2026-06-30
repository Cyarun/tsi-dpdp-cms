package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Service exposing the global DATA-POINT CATALOG — the single source of truth
 * for "what personal data-point kinds can exist" on the DPDPA.center platform.
 *
 * The catalog is GLOBAL (no fiduciary scoping): it is reference data shared
 * across all tenants. Per-tenant configuration (which data points a fiduciary
 * actually processes) is handled by downstream services.
 *
 * One function:
 *   list_data_points — return all catalog rows ordered by category, id.
 *
 * Read is ADMIN-GATED (validate() = processAdminHeader) so only authenticated
 * operators can retrieve the catalog. This matches the security posture of every
 * other service in this package.
 *
 * vAIb (mydata-ui P0) — canonical catalog backing RoPA, Policy, My-Data toggles.
 */
public class DataPointCatalog implements Action {

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
                case "list_data_points":
                    handleListDataPoints(input, req, res);
                    break;
                default:
                    OutputProcessor.errorResponse(res, 400, "Bad Request", "Unknown function.", req.getRequestURI());
            }
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, 500, "Internal Error", e.getMessage(), req.getRequestURI());
        }
    }

    /**
     * SELECT all rows from data_point_catalog ordered by category then id.
     *
     * Body: { _func: "list_data_points" }
     * Returns: a bare JSONArray of { id, label, category, sensitivity, description } objects.
     *
     * Global read — no fiduciary scoping; the catalog is the same for all tenants.
     * Admin-gated via validate() / processAdminHeader.
     */
    private void handleListDataPoints(JSONObject input, HttpServletRequest req, HttpServletResponse res) throws SQLException {
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();

            String sql = "SELECT id, label, category, sensitivity, description "
                    + "FROM data_point_catalog "
                    + "ORDER BY category, id";

            pstmt = conn.prepareStatement(sql);
            rs = pstmt.executeQuery();

            JSONArray arr = new JSONArray();
            while (rs.next()) {
                JSONObject row = new JSONObject();
                row.put("id",          rs.getString("id"));
                row.put("label",       rs.getString("label"));
                row.put("category",    rs.getString("category"));
                row.put("sensitivity", rs.getString("sensitivity"));
                row.put("description", rs.getString("description")); // may be null — fine
                arr.add(row);
            }

            OutputProcessor.send(res, HttpServletResponse.SC_OK, arr);
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
