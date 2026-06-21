package org.tsicoop.dpdpcms.util;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.tsicoop.dpdpcms.framework.PoolDB;

import java.sql.*;
import java.util.*;

public class RopaDeriver {

    /**
     * Reads a published consent policy and upserts one draft ropa_entry per
     * processing purpose. On re-publish (new policy version), existing entries
     * matched by (fiduciary_id, source_purpose_id) are updated in place — all
     * fields overwritten from the policy and a history snapshot taken. Active
     * entries are moved to under_review so the DPO re-approves the changes.
     *
     * @return UUID of the last created/updated entry, or null on failure.
     */
    public static UUID deriveFromPolicy(String policyId, String version, UUID fiduciaryId) throws Exception {
        return deriveFromPolicy(policyId, version, fiduciaryId, null, null);
    }

    /**
     * vAIb-aqip — AUTOFILL overload (the "expedite engine"). Same upsert as above, but
     * when the source policy does NOT carry the structured fields the RoPA completeness
     * checklist (RopaValidator) requires — retention_period_days, retention_start_event,
     * security_measures — we BACKFILL them from the chosen VERTICAL template defaults +
     * the detected apps, so the DERIVED entries reach 'complete' (all-green checklist)
     * and become approvable by the DPO WITHOUT manual typing. The autofill ONLY fills
     * GAPS: any value the policy DOES carry always wins (the owner's wizard choices are
     * never overwritten). vertical may be null (-> a safe DPDPA baseline); appNames may
     * be null/empty (-> a generic security-measures sentence).
     *
     * @param vertical the owner-confirmed business vertical (datacentre/education/
     *                 finance/health/media/retail/social), or null for the baseline.
     * @param appNames detected processor/app names to name in the security-measures text.
     */
    public static UUID deriveFromPolicy(String policyId, String version, UUID fiduciaryId,
                                        String vertical, List<String> appNames) throws Exception {
        String policyContentStr = loadPolicyContent(policyId, version, fiduciaryId);
        if (policyContentStr == null) return null;

        JSONObject content = (JSONObject) new JSONParser().parse(policyContentStr);
        if (content == null || content.isEmpty()) return null;

        String lang = content.containsKey("en") ? "en" : (String) content.keySet().iterator().next();
        JSONObject langObj = (JSONObject) content.get(lang);
        if (langObj == null) return null;

        JSONArray purposes = (JSONArray) langObj.get("data_processing_purposes");
        if (purposes == null || purposes.isEmpty()) return null;

        // vAIb-aqip: resolve the vertical defaults once (null vertical -> baseline).
        VerticalDefaults vd = VerticalDefaults.forVertical(vertical);

        // Policy-level fields shared across all purposes
        JSONArray dataSubjectCategories = extractOrDefault(
                (JSONArray) langObj.get("data_subject_categories"), "data_principal");
        String securityMeasures = (String) langObj.get("security_measures");
        // AUTOFILL GAP: a policy that does not carry security_measures would leave every
        // derived entry incomplete (RopaValidator requires it). Backfill from the
        // vertical default + the detected apps so the entry is approvable.
        if (securityMeasures == null || securityMeasures.trim().isEmpty()) {
            securityMeasures = vd.securityMeasures(appNames);
        }
        JSONArray processorsArr = langObj.get("processors") instanceof JSONArray
                ? (JSONArray) langObj.get("processors") : new JSONArray();
        JSONArray crossBorderArr = langObj.get("cross_border_transfers") instanceof JSONArray
                ? (JSONArray) langObj.get("cross_border_transfers") : new JSONArray();

        UUID lastId = null;
        for (Object obj : purposes) {
            JSONObject purpose = (JSONObject) obj;

            String purposeId = (String) purpose.get("id");
            if (purposeId == null || purposeId.isEmpty()) continue;

            String activityName = (String) purpose.get("name");
            if (activityName == null || activityName.isEmpty()) activityName = purposeId;

            String purposeText = (String) purpose.get("description");
            if (purposeText == null || purposeText.isEmpty()) purposeText = activityName;

            String legalBasis = normalizeLegalBasis((String) purpose.get("legal_basis"));

            JSONArray dataCats = purpose.get("data_categories_involved") instanceof JSONArray
                    ? (JSONArray) purpose.get("data_categories_involved") : new JSONArray();

            Integer retentionDays = null;
            Object valObj  = purpose.get("retention_duration_value");
            Object unitObj = purpose.get("retention_duration_unit");
            if (valObj != null && unitObj != null) {
                try {
                    retentionDays = toDays((int)(long) valObj, unitObj.toString().toUpperCase());
                } catch (Exception ignored) {}
            }
            // AUTOFILL GAP (vAIb-aqip): the checklist requires retention_period_days > 0.
            // When the policy purpose carries no usable retention, use the vertical default
            // (legal-basis aware — consent purposes get the shorter window).
            if (retentionDays == null || retentionDays <= 0) {
                retentionDays = vd.retentionDays(legalBasis);
            }
            String retentionStartEvent = (String) purpose.get("retention_start_event");
            // AUTOFILL GAP: the checklist requires retention_start_event ∈ {COLLECTION,
            // CESSATION}. Default per the vertical when absent/invalid.
            if (retentionStartEvent == null || !("COLLECTION".equals(retentionStartEvent)
                    || "CESSATION".equals(retentionStartEvent))) {
                retentionStartEvent = vd.retentionStartEvent();
            }

            // Filter processors and cross-border transfers to those named by this purpose
            Set<String> rtp = new HashSet<>();
            if (purpose.get("recipients_or_third_parties") instanceof JSONArray) {
                for (Object o : (JSONArray) purpose.get("recipients_or_third_parties"))
                    if (o != null) rtp.add(o.toString().toLowerCase());
            }
            JSONArray filteredProcessors = rtp.isEmpty() ? processorsArr : new JSONArray();
            JSONArray filteredCrossBorder = rtp.isEmpty() ? crossBorderArr : new JSONArray();
            if (!rtp.isEmpty()) {
                for (Object o : processorsArr) {
                    String name = (String) ((JSONObject) o).get("name");
                    if (name != null && rtp.contains(name.toLowerCase())) filteredProcessors.add(o);
                }
                for (Object o : crossBorderArr) {
                    Object proc = ((JSONObject) o).get("processor");
                    if (proc == null || rtp.contains(proc.toString().toLowerCase())) filteredCrossBorder.add(o);
                }
            }

            JSONObject existing = findExisting(fiduciaryId, purposeId);
            if (existing != null) {
                lastId = updateEntry(existing, policyId, activityName, purposeText, legalBasis,
                        dataCats, dataSubjectCategories, securityMeasures,
                        filteredProcessors, filteredCrossBorder, retentionDays, retentionStartEvent);
            } else {
                lastId = insertEntry(fiduciaryId, purposeId, activityName, purposeText, legalBasis,
                        dataCats, dataSubjectCategories, policyId, securityMeasures,
                        filteredProcessors, filteredCrossBorder, retentionDays, retentionStartEvent);
                if (lastId != null) snapshotInitialHistory(lastId);
            }
        }
        return lastId;
    }

    // --- Upsert helpers ---

    private static JSONObject findExisting(UUID fiduciaryId, String purposeId) throws SQLException {
        String sql = "SELECT id, version, status, linked_policy_ids FROM ropa_entries " +
                     "WHERE fiduciary_id = ? AND source_purpose_id = ? AND status != 'retired' LIMIT 1";
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            pstmt.setString(2, purposeId);
            rs = pstmt.executeQuery();
            if (!rs.next()) return null;
            JSONObject e = new JSONObject();
            e.put("id",               rs.getObject("id").toString());
            e.put("version",          rs.getLong("version"));
            e.put("status",           rs.getString("status"));
            e.put("linked_policy_ids", rs.getString("linked_policy_ids"));
            return e;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private static UUID updateEntry(JSONObject existing, String policyId,
                                    String activityName, String purposeText, String legalBasis,
                                    JSONArray dataCats, JSONArray dataSubjectCats,
                                    String securityMeasures, JSONArray processors,
                                    JSONArray crossBorder, Integer retentionDays,
                                    String retentionStartEvent) throws Exception {
        UUID entryId = UUID.fromString((String) existing.get("id"));
        int  version = ((Long) existing.get("version")).intValue();

        // Snapshot before overwriting
        snapshotForUpdate(entryId, version);

        // Append new policy ID to linked_policy_ids if not already present
        String appendSql = "UPDATE ropa_entries SET " +
                "activity_name = ?, purpose = ?, legal_basis = ?, " +
                "data_categories = ?::jsonb, data_subject_categories = ?::jsonb, " +
                "security_measures = ?, processors = ?::jsonb, " +
                "cross_border_transfers = ?::jsonb, " +
                "retention_period_days = ?, retention_start_event = ?, " +
                "linked_policy_ids = CASE " +
                "  WHEN linked_policy_ids @> ?::jsonb THEN linked_policy_ids " +
                "  ELSE linked_policy_ids || ?::jsonb " +
                "END, " +
                "status = CASE WHEN status = 'active' THEN 'under_review' ELSE status END, " +
                "version = version + 1, updated_at = NOW() " +
                "WHERE id = ?";

        String policyJsonElement = "[\"" + policyId + "\"]";

        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(appendSql);
            pstmt.setString(1, activityName);
            pstmt.setString(2, purposeText);
            pstmt.setString(3, legalBasis);
            pstmt.setString(4, dataCats.toJSONString());
            pstmt.setString(5, dataSubjectCats.toJSONString());
            pstmt.setString(6, securityMeasures);
            pstmt.setString(7, processors.toJSONString());
            pstmt.setString(8, crossBorder.toJSONString());
            if (retentionDays != null) pstmt.setInt(9, retentionDays);
            else pstmt.setNull(9, Types.INTEGER);
            pstmt.setString(10, retentionStartEvent);
            pstmt.setString(11, policyJsonElement);
            pstmt.setString(12, policyJsonElement);
            pstmt.setObject(13, entryId);
            pstmt.executeUpdate();
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
        return entryId;
    }

    private static UUID insertEntry(UUID fiduciaryId, String purposeId,
                                    String activityName, String purposeText, String legalBasis,
                                    JSONArray dataCats, JSONArray dataSubjectCats,
                                    String policyId, String securityMeasures,
                                    JSONArray processors, JSONArray crossBorder,
                                    Integer retentionDays, String retentionStartEvent) throws SQLException {
        String sql = "INSERT INTO ropa_entries " +
                "(fiduciary_id, source_purpose_id, activity_name, purpose, legal_basis, " +
                "data_categories, data_subject_categories, linked_policy_ids, " +
                "security_measures, processors, cross_border_transfers, " +
                "retention_period_days, retention_start_event, status, version) " +
                "VALUES (?, ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?::jsonb, ?, ?::jsonb, ?::jsonb, ?, ?, 'draft', 1) " +
                "RETURNING id";

        JSONArray linkedPolicyIds = new JSONArray();
        linkedPolicyIds.add(policyId);

        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, fiduciaryId);
            pstmt.setString(2, purposeId);
            pstmt.setString(3, activityName);
            pstmt.setString(4, purposeText);
            pstmt.setString(5, legalBasis);
            pstmt.setString(6, dataCats.toJSONString());
            pstmt.setString(7, dataSubjectCats.toJSONString());
            pstmt.setString(8, linkedPolicyIds.toJSONString());
            pstmt.setString(9, securityMeasures);
            pstmt.setString(10, processors.toJSONString());
            pstmt.setString(11, crossBorder.toJSONString());
            if (retentionDays != null) pstmt.setInt(12, retentionDays);
            else pstmt.setNull(12, Types.INTEGER);
            pstmt.setString(13, retentionStartEvent);
            rs = pstmt.executeQuery();
            return rs.next() ? (UUID) rs.getObject(1) : null;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    // --- History helpers ---

    private static void snapshotInitialHistory(UUID entryId) throws SQLException {
        String sql = "INSERT INTO ropa_history (ropa_entry_id, version, snapshot) " +
                "SELECT id, version, to_jsonb(ropa_entries) FROM ropa_entries WHERE id = ?";
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, entryId);
            pstmt.executeUpdate();
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    private static void snapshotForUpdate(UUID entryId, int currentVersion) throws SQLException {
        String sql = "INSERT INTO ropa_history (ropa_entry_id, version, snapshot) " +
                "SELECT id, version, to_jsonb(ropa_entries) FROM ropa_entries WHERE id = ? " +
                "ON CONFLICT DO NOTHING";
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setObject(1, entryId);
            pstmt.executeUpdate();
        } finally {
            pool.cleanup(null, pstmt, conn);
        }
    }

    // --- DB loader ---

    private static String loadPolicyContent(String policyId, String version, UUID fiduciaryId) throws SQLException {
        String sql = "SELECT policy_content FROM consent_policies " +
                "WHERE id = ? AND version = ? AND fiduciary_id = ? AND status IN ('ACTIVE', 'UNDER_REVIEW')";
        PoolDB pool = new PoolDB();
        Connection conn = null; PreparedStatement pstmt = null; ResultSet rs = null;
        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, policyId);
            pstmt.setString(2, version);
            pstmt.setObject(3, fiduciaryId);
            rs = pstmt.executeQuery();
            return rs.next() ? rs.getString(1) : null;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    // --- Utility ---

    private static String normalizeLegalBasis(String raw) {
        if (raw == null) return "consent";
        switch (raw.toLowerCase().replace(" ", "_")) {
            case "legal_obligation": return "legal_obligation";
            case "vital_interest":   return "vital_interest";
            case "legitimate_use":   return "legitimate_use";
            default:                 return "consent";
        }
    }

    private static int toDays(int value, String unit) {
        switch (unit) {
            case "YEARS":   return value * 365;
            case "MONTHS":  return value * 30;
            case "DAYS":    return value;
            case "HOURS":   return Math.max(1, value / 24);
            case "MINUTES": return Math.max(1, value / 1440);
            default:        return value;
        }
    }

    private static JSONArray extractOrDefault(JSONArray src, String fallback) {
        if (src != null && !src.isEmpty()) return src;
        JSONArray a = new JSONArray();
        a.add(fallback);
        return a;
    }

    // -----------------------------------------------------------------------
    // vAIb-aqip — VERTICAL TEMPLATE DEFAULTS (the RoPA autofill source).
    // Per-vertical sane DPDPA-aligned defaults used to BACKFILL the completeness-
    // checklist gaps (retention_period_days, retention_start_event, security_measures)
    // when the source policy did not carry them, so derived entries reach 'complete'
    // and become DPO-approvable without manual typing. These are GAP-FILLERS only — any
    // value the policy DOES carry always wins. The 7 verticals mirror the wizard's
    // suggest_vertical (services/gateway/core/onboarding_draft.py:191).
    // -----------------------------------------------------------------------
    private static final class VerticalDefaults {
        final int retentionDaysConsent;     // shorter window for consent-based purposes
        final int retentionDaysNonConsent;  // longer window for legal/legit/vital
        final String retentionStartEvent;   // COLLECTION or CESSATION
        final String securityBaseline;      // vertical-appropriate safeguards sentence

        private VerticalDefaults(int consentDays, int nonConsentDays,
                                 String startEvent, String securityBaseline) {
            this.retentionDaysConsent = consentDays;
            this.retentionDaysNonConsent = nonConsentDays;
            this.retentionStartEvent = startEvent;
            this.securityBaseline = securityBaseline;
        }

        // Legal-basis-aware retention: consent purposes default to the shorter window
        // (data minimisation); legal_obligation/legitimate_use/vital_interest to the
        // longer one (records often must be kept post-relationship).
        int retentionDays(String legalBasis) {
            return "consent".equalsIgnoreCase(legalBasis)
                    ? retentionDaysConsent : retentionDaysNonConsent;
        }

        String retentionStartEvent() { return retentionStartEvent; }

        // Security-measures text = the vertical baseline + the DETECTED apps named as
        // sub-processors under DPAs (DPDP Act Section 8(5)). Apps are HTML-escaped: this
        // text is stored on the RoPA + shown on the DPO console (a principal-facing
        // surface), and app names are tenant-controlled.
        String securityMeasures(List<String> appNames) {
            StringBuilder sb = new StringBuilder(securityBaseline);
            if (appNames != null && !appNames.isEmpty()) {
                List<String> safe = new ArrayList<>();
                for (String n : appNames) {
                    if (n == null) continue;
                    String t = n.trim();
                    if (t.isEmpty()) continue;
                    safe.add(escape(t.length() > 80 ? t.substring(0, 80) : t));
                    if (safe.size() >= 12) break;  // bound the list
                }
                if (!safe.isEmpty()) {
                    sb.append(" Sub-processors engaged under data-processing agreements: ")
                      .append(String.join(", ", safe)).append(".");
                }
            }
            return sb.toString();
        }

        private static String escape(String s) {
            return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    .replace("\"", "&quot;").replace("'", "&#39;");
        }

        static VerticalDefaults forVertical(String vertical) {
            String v = vertical == null ? "" : vertical.trim().toLowerCase();
            switch (v) {
                case "finance":
                    // RBI/PMLA records often retained ~8y after relationship end.
                    return new VerticalDefaults(365 * 2, 365 * 8, "CESSATION",
                        "Encryption in transit (TLS 1.2+) and at rest (AES-256), role-based "
                        + "access control, audit logging, and periodic access reviews aligned to "
                        + "financial-sector record-keeping obligations.");
                case "health":
                    // Health records: long retention from cessation of care.
                    return new VerticalDefaults(365 * 3, 365 * 7, "CESSATION",
                        "Encryption in transit (TLS 1.2+) and at rest (AES-256), strict need-to-know "
                        + "access control for sensitive health data, audit logging, and breach-response "
                        + "procedures.");
                case "education":
                    return new VerticalDefaults(365 * 2, 365 * 5, "CESSATION",
                        "Encryption in transit and at rest, role-based access control, audit logging, "
                        + "and retention of academic records per institutional policy.");
                case "datacentre":
                    return new VerticalDefaults(365, 365 * 3, "CESSATION",
                        "Encryption in transit and at rest, network segmentation, role-based access "
                        + "control, continuous monitoring, and audit logging.");
                case "media":
                    return new VerticalDefaults(365, 365 * 2, "COLLECTION",
                        "Encryption in transit and at rest, role-based access control, and audit "
                        + "logging for content and audience data.");
                case "social":
                    return new VerticalDefaults(365, 365 * 2, "CESSATION",
                        "Encryption in transit and at rest, role-based access control, audit logging, "
                        + "and account-deletion workflows for member/community data.");
                case "retail":
                default:
                    // Broadest commerce default (also the baseline when vertical is null).
                    return new VerticalDefaults(365, 365 * 3, "CESSATION",
                        "Encryption in transit (TLS 1.2+) and at rest, role-based access control, "
                        + "audit logging, and least-privilege handling of customer data.");
            }
        }
    }
}
