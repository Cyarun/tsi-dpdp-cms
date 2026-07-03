package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*;
import org.tsicoop.dpdpcms.service.v1.dpia.DpiaEngine;
import org.tsicoop.dpdpcms.service.v1.dpia.FiduciaryContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.sql.*;
import java.time.Instant;
import java.util.*;

/**
 * NATIVE DPIA service — the FIRST strangler-fig slice off fabric (vAIb-86uz).
 *
 * <p>Computes the DPB-grade DPIA report ENTIRELY inside the CMS on this tenant's OWN RoPA data:
 * NO call to fabric, NO call to OpenMetadata, NO network egress. Tenant isolation is the CMS's own
 * multi-tenancy — the {@code fiduciary_id} scope is SERVER-DERIVED via
 * {@link InputProcessor#resolveTenantScope} (never the raw body value), mirroring {@code Ropa.java}
 * EXACTLY (the vAIb-ae11 tenant-scope discipline). A DPO for tenant A can never see tenant B's DPIA.
 *
 * <p>The engine ({@link DpiaEngine}) is a verbatim, parity-tested port of {@code dpia_report.py};
 * this service only READS the tenant's active RoPA rows + derives a PII-free {@link FiduciaryContext}
 * (mirroring fabric's {@code _derive_fiduciary_ctx}) and hands both to the pure in-process engine.
 * The response shape ({@code {ok:true, report:<engine output>}}) matches what {@code dpia.html} renders.
 */
public class Dpia implements Action {

    // Legal-basis enums that count as a consent basis for consent-manager derivation
    // (mirrors DpiaEngine.CONSENT_BASES and fabric _CONSENT_LEGAL_BASES).
    private static final Set<String> CONSENT_BASES =
            new HashSet<>(Collections.singletonList("consent"));

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
                case "generate_report":   handleGenerateReport(input, res, req);   break;
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

    // --- Handler ---

    private void handleGenerateReport(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        // vAIb-ae11 tenant boundary: server-derived fiduciary_id (NEVER the raw body value).
        // Identical seam to Ropa.resolveEffectiveFid — the CMS's own multitenancy IS the isolation.
        UUID fiduciaryId = InputProcessor.resolveTenantScope(req, res, true);
        if (fiduciaryId == null) return;  // error already sent (401/403)

        // Read ONLY this tenant's ACTIVE RoPA rows (mirrors Ropa.listEntriesWithConsentCount:
        // WHERE fiduciary_id = ? AND status = 'active'). Metadata + counts only — no principal PII.
        JSONArray ropaRows = listActiveRopaWithConsentCount(fiduciaryId);

        // Adapt each RoPA row to the engine's expected row shape (JSONB text -> List/Map).
        List<Map<String, Object>> activities = new ArrayList<>();
        for (Object o : ropaRows) {
            if (o instanceof JSONObject) {
                activities.add(adaptRow((JSONObject) o));
            }
        }

        // Derive the PII-free FiduciaryContext from the CMS's OWN signals (mirrors fabric
        // _derive_fiduciary_ctx: has_dpo from dpo_id/dpo_user_id, has_consent_manager from
        // genuine consent_count, children from subject categories; auditor/breach honest gaps).
        FiduciaryContext ctx = deriveFiduciaryContext(fiduciaryId, ropaRows);

        String reportingPeriod = clip((String) input.get("reporting_period"), 64);
        String generatedAt = Instant.now().toString();

        // Pure, in-process, deterministic — no fabric/OM handshake.
        Map<String, Object> report = DpiaEngine.buildDpiaReport(activities, ctx, generatedAt, reportingPeriod);

        // Response shape dpia.html expects: { ok: true, report: <engine output> }.
        JSONObject out = new JSONObject();
        out.put("ok", true);
        out.put("report", toJson(report));
        OutputProcessor.send(res, HttpServletResponse.SC_OK, out);
    }

    /**
     * vAIb-zv2g — a compact DPIA summary ({@code dpia_status}, {@code dpia_gaps}) for a SERVER-DERIVED
     * fiduciary, reusing the exact same engine pipeline as {@code generate_report} (RoPA read ->
     * adapt -> FiduciaryContext -> {@link DpiaEngine#buildDpiaReport}). The AdminDash overview cards
     * call this. Callers MUST pass an already-tenant-resolved fiduciaryId (from resolveTenantScope) —
     * this method does NO scoping of its own and NEVER accepts a body value. Returns just the two
     * headline fields the posture card needs (not the full 11-section report).
     */
    public JSONObject computeSummaryForFiduciary(UUID fiduciaryId) throws SQLException {
        JSONArray ropaRows = listActiveRopaWithConsentCount(fiduciaryId);
        List<Map<String, Object>> activities = new ArrayList<>();
        for (Object o : ropaRows) {
            if (o instanceof JSONObject) activities.add(adaptRow((JSONObject) o));
        }
        FiduciaryContext ctx = deriveFiduciaryContext(fiduciaryId, ropaRows);
        Map<String, Object> report = DpiaEngine.buildDpiaReport(activities, ctx, Instant.now().toString(), null);
        Object overall = report.get("overall");
        JSONObject out = new JSONObject();
        String status = "unknown";
        int gaps = 0;
        if (overall instanceof Map) {
            Object s = ((Map<?, ?>) overall).get("overall_compliance_status");
            if (s == null) s = ((Map<?, ?>) overall).get("compliance_status");
            if (s != null) status = String.valueOf(s);
            Object g = ((Map<?, ?>) overall).get("total_gaps");
            if (g instanceof Number) gaps = ((Number) g).intValue();
        }
        out.put("dpia_status", status);
        out.put("dpia_gaps", gaps);
        return out;
    }

    // --- RoPA read (tenant-scoped, active only) ---

    /**
     * This tenant's ACTIVE RoPA rows plus a per-activity genuine consent count. Same query shape as
     * {@code Ropa.listEntriesWithConsentCount} (the DPO-console coverage read): scoped
     * {@code WHERE r.fiduciary_id = ? AND r.status = 'active'}. Category columns are JSONB and come
     * back as raw JSON strings — the engine adapter parses them.
     */
    private JSONArray listActiveRopaWithConsentCount(UUID fiduciaryId) throws SQLException {
        String sql = "SELECT r.id, r.fiduciary_id, r.app_id, r.activity_name, r.purpose, r.legal_basis, " +
                "r.data_categories, r.data_subject_categories, r.retention_period_days, r.retention_start_event, " +
                "r.processors, r.cross_border_transfers, r.security_measures, r.dpo_id, r.linked_policy_ids, " +
                "r.source_purpose_id, r.status, r.version, r.created_at, r.updated_at, " +
                "COUNT(*) FILTER (WHERE c.consent_granted = TRUE) AS consent_count " +
                "FROM ropa_entries r " +
                "LEFT JOIN LATERAL (" +
                "  SELECT DISTINCT ON (cr.user_id) cr.user_id, (dp->>'consent_granted')::boolean AS consent_granted " +
                "  FROM consent_records cr, jsonb_array_elements(cr.data_point_consents) AS dp " +
                "  WHERE cr.fiduciary_id = r.fiduciary_id AND dp->>'data_point_id' = r.source_purpose_id " +
                "  ORDER BY cr.user_id, cr.created_at DESC" +
                ") c ON TRUE " +
                "WHERE r.fiduciary_id = ? AND r.status = 'active' " +
                "GROUP BY r.id " +
                "ORDER BY r.created_at DESC";

        JSONArray result = new JSONArray();
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                JSONObject e = new JSONObject();
                e.put("activity_name",          rs.getString("activity_name"));
                e.put("purpose",                rs.getString("purpose"));
                e.put("legal_basis",            rs.getString("legal_basis"));
                e.put("data_categories",        rs.getString("data_categories"));
                e.put("data_subject_categories",rs.getString("data_subject_categories"));
                e.put("retention_period_days",  rs.getObject("retention_period_days") != null ? (long) rs.getInt("retention_period_days") : null);
                e.put("retention_start_event",  rs.getString("retention_start_event"));
                e.put("processors",             rs.getString("processors"));
                e.put("cross_border_transfers", rs.getString("cross_border_transfers"));
                e.put("security_measures",      rs.getString("security_measures"));
                e.put("dpo_id",                 rs.getObject("dpo_id") != null ? rs.getObject("dpo_id").toString() : null);
                e.put("status",                 rs.getString("status"));
                e.put("consent_count",          rs.getLong("consent_count"));
                result.add(e);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
        return result;
    }

    // --- Engine row adaptation (JSONB text -> engine's expected shape) ---

    /**
     * Map ONE CMS RoPA row onto the metadata shape {@link DpiaEngine#buildDpiaReport} reads
     * (its ACTIVITY_METADATA_FIELDS). The engine defensively re-projects to its allow-list, so we
     * only need to shape the fields it consumes. PII-free: only category labels / enums / counts.
     *
     * <p>JSONB text columns (data_categories, data_subject_categories, processors,
     * cross_border_transfers) are parsed from their stored JSON-array strings into List/Map so the
     * engine's label / processor / cross-border logic reads them the same way it reads the
     * fabric-supplied rows.
     *
     * <p>{@code is_special_category} and {@code consent_mechanism} are not stored as first-class
     * RoPA columns; we derive them faithfully (mirrors fabric _bridge_draft_entry_to_activity):
     * a consent-basis activity with genuine captured consent gets a value-free mechanism token so
     * §6 is assessed truthfully; special-category is inferred from data_categories labels.
     */
    private Map<String, Object> adaptRow(JSONObject row) {
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("activity_name",           str(row.get("activity_name"), "Unnamed activity"));
        a.put("purpose",                 str(row.get("purpose"), ""));
        String legalBasis = str(row.get("legal_basis"), "");
        a.put("legal_basis",             legalBasis);
        List<Object> cats = parseJsonArray(row.get("data_categories"));
        a.put("data_categories",         cats);
        a.put("data_subject_categories", parseJsonArray(row.get("data_subject_categories")));
        a.put("retention_period_days",   row.get("retention_period_days"));
        a.put("retention_start_event",   str(row.get("retention_start_event"), ""));
        a.put("processors",              parseJsonArray(row.get("processors")));
        a.put("cross_border_transfers",  parseJsonArray(row.get("cross_border_transfers")));
        a.put("security_measures",       str(row.get("security_measures"), ""));
        a.put("status",                  str(row.get("status"), ""));

        // is_special_category: inferred from category labels (the CMS RoPA has no dedicated column).
        a.put("is_special_category", hasSpecialCategory(cats));

        // consent_mechanism: for a consent-basis activity that has genuine captured consent, record
        // a value-free token so the §6 "consent_without_mechanism" gap does not false-fire on a
        // legitimately consent-based, actively-consented activity (mirrors fabric bridge). Metadata
        // only — never a principal's actual consent record.
        String lb = legalBasis.trim().toLowerCase();
        long consentCount = row.get("consent_count") instanceof Long ? (Long) row.get("consent_count") : 0L;
        if (CONSENT_BASES.contains(lb) && consentCount > 0) {
            a.put("consent_mechanism", "consent_capture");
        }
        return a;
    }

    private boolean hasSpecialCategory(List<Object> cats) {
        // Conservative label-only heuristic for sensitive/special categories. Value-free.
        for (Object c : cats) {
            if (c == null) continue;
            String low = String.valueOf(c).toLowerCase();
            if (low.contains("health") || low.contains("medical") || low.contains("biometric")
                    || low.contains("genetic") || low.contains("financial") || low.contains("bank")
                    || low.contains("religio") || low.contains("caste") || low.contains("sexual")
                    || low.contains("political") || low.contains("sensitive") || low.contains("special")) {
                return true;
            }
        }
        return false;
    }

    // --- FiduciaryContext derivation (PII-free; mirrors fabric _derive_fiduciary_ctx) ---

    /**
     * Build the PII-free {@link FiduciaryContext} from the CMS's OWN tenant-scoped signals — never
     * from client input. Mirrors fabric {@code _derive_fiduciary_ctx}:
     * <ul>
     *   <li>{@code fiduciary_ref} = masked suffix ("..." + last 6 of the fiduciary id) — never raw.
     *   <li>{@code is_significant_data_fiduciary} = the fiduciaries row flag.
     *   <li>{@code has_dpo} = a DPO is assigned to any active RoPA row (dpo_id) OR the fiduciary
     *       row carries a dpo_user_id.
     *   <li>{@code has_consent_manager} = genuine consent captured (any activity consent_count > 0).
     *   <li>{@code processes_children_data} = TRUE if a subject category evidences it, else null
     *       (not assessed -> drives the §9 org gap), matching the Python three-state.
     *   <li>{@code has_grievance_mechanism} = the tenant has at least one grievance record (the CMS
     *       HAS this read; a live grievance surface evidences the mechanism).
     *   <li>{@code has_auditor} / {@code has_breach_process} = honest gaps (no CMS read on this seam
     *       yet) — fail closed, never fabricated, exactly as fabric does.
     * </ul>
     */
    private FiduciaryContext deriveFiduciaryContext(UUID fiduciaryId, JSONArray ropaRows) throws SQLException {
        boolean isSdf = false;
        boolean hasDpoOnFiduciary = false;
        // Read the fiduciary row (server-side, own tenant) for the SDF flag. The fiduciaries
        // table has no dpo_user_id column in this schema (it was a planned field never added),
        // so has_dpo is derived solely from the RoPA rows' dpo_id below (the real mechanism).
        // ponytail: don't SELECT a column that doesn't exist — it crashed the whole DPIA report.
        String fidSql = "SELECT is_significant_data_fiduciary FROM fiduciaries WHERE id = ?";
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(fidSql);
            pstmt.setObject(1, fiduciaryId);
            rs = pstmt.executeQuery();
            if (rs.next()) {
                isSdf = rs.getBoolean("is_significant_data_fiduciary");
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }

        boolean hasDpo = hasDpoOnFiduciary;
        boolean hasConsentManager = false;
        Boolean children = null; // null = not assessed (three-state, matches Python Optional[bool])
        for (Object o : ropaRows) {
            if (!(o instanceof JSONObject)) continue;
            JSONObject e = (JSONObject) o;
            // A registered DPO assigned to the RoPA (CMS dpo_id).
            Object dpoId = e.get("dpo_id");
            if (dpoId != null && !String.valueOf(dpoId).isEmpty()) {
                hasDpo = true;
            }
            // Genuine consent captured for this activity (CMS consent_count).
            long cc = e.get("consent_count") instanceof Long ? (Long) e.get("consent_count") : 0L;
            if (cc > 0) {
                hasConsentManager = true;
            }
            // Children signal from subject categories (label-only, never a subject's data).
            for (Object s : parseJsonArray(e.get("data_subject_categories"))) {
                if (s == null) continue;
                String low = String.valueOf(s).toLowerCase();
                if (low.contains("child") || low.contains("minor")
                        || low.contains("under_18") || low.contains("under-18")) {
                    children = Boolean.TRUE;
                }
            }
        }

        boolean hasGrievance = tenantHasGrievanceMechanism(fiduciaryId);

        return FiduciaryContext.builder()
                .fiduciaryRef(maskRef(fiduciaryId))
                .isSignificantDataFiduciary(isSdf)
                .hasDpo(hasDpo)
                .hasGrievanceMechanism(hasGrievance)
                .hasAuditor(false)        // no CMS read on this seam -> honest gap (fail closed)
                .hasBreachProcess(false)  // no CMS read on this seam -> honest gap (fail closed)
                .processesChildrenData(children)
                .hasConsentManager(hasConsentManager)
                .build();
    }

    /**
     * True when the tenant has a live grievance surface (at least one grievance record). The CMS
     * owns this data natively, so we derive it honestly from the tenant's own grievances table
     * rather than leaving it a blind gap. Scoped to the caller's fiduciary. On any error, fail
     * closed (false) — an honest gap is safer than a fabricated pass.
     */
    private boolean tenantHasGrievanceMechanism(UUID fiduciaryId) {
        String sql = "SELECT EXISTS(SELECT 1 FROM grievances WHERE fiduciary_id = ?)";
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
            return rs.next() && rs.getBoolean(1);
        } catch (Exception e) {
            System.err.println("[Dpia] grievance-mechanism check failed (fail closed): " + e.getMessage());
            return false;
        } finally {
            if (pool != null) try { pool.cleanup(rs, pstmt, conn); } catch (Exception ignored) {}
        }
    }

    /** Masked fiduciary reference: "..." + last 6 chars. Never the raw id. Mirrors fabric _mask_ref. */
    private String maskRef(UUID fiduciaryId) {
        String s = fiduciaryId == null ? "" : fiduciaryId.toString();
        return s.length() > 6 ? "..." + s.substring(s.length() - 6) : "...(short)";
    }

    // --- JSON helpers ---

    /**
     * Parse a stored JSONB text field into a List. RoPA JSONB columns come back as JSON-array
     * strings via the JDBC read; the engine expects a List. Non-array / unparseable -> empty list
     * (defensive), so a malformed row never crashes the DPIA path.
     */
    private List<Object> parseJsonArray(Object val) {
        List<Object> out = new ArrayList<>();
        if (val == null) return out;
        if (val instanceof JSONArray) {
            for (Object o : (JSONArray) val) out.add(o);
            return out;
        }
        if (val instanceof List) {
            out.addAll((List<?>) val);
            return out;
        }
        String s = String.valueOf(val).trim();
        if (s.isEmpty()) return out;
        try {
            Object parsed = new JSONParser().parse(s);
            if (parsed instanceof JSONArray) {
                for (Object o : (JSONArray) parsed) out.add(o);
            }
        } catch (Exception ignored) { /* malformed -> empty list */ }
        return out;
    }

    private String str(Object v, String def) {
        if (v == null) return def;
        return String.valueOf(v);
    }

    private String clip(String v, int limit) {
        if (v == null) return "";
        return v.length() > limit ? v.substring(0, limit) : v;
    }

    /**
     * Convert the engine's plain java.util Map/List tree into org.json.simple types so
     * OutputProcessor serialises it correctly (the engine is JSON-lib-agnostic by design).
     */
    @SuppressWarnings("unchecked")
    private Object toJson(Object v) {
        if (v instanceof Map) {
            JSONObject o = new JSONObject();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) {
                o.put(e.getKey(), toJson(e.getValue()));
            }
            return o;
        }
        if (v instanceof List) {
            JSONArray arr = new JSONArray();
            for (Object item : (List<Object>) v) arr.add(toJson(item));
            return arr;
        }
        return v;
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return "POST".equalsIgnoreCase(method) && InputProcessor.validate(req, res);
    }
}
