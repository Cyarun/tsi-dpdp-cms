package org.tsicoop.dpdpcms.service.v1.dpia;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * DPIA report builder — a PURE, deterministic assembler.
 *
 * <p>VERBATIM Java port of {@code engine_source/dpia_report.py} (the de-risked Python PoC). Keeps
 * the SAME citation strings, remediation text, gap logic, status roll-up, and 11-section Board
 * report structure so the Java output is byte-for-byte equivalent to the Python for a given input.
 *
 * <p>{@link #buildDpiaReport} maps a tenant's REAL Record of Processing Activities (RoPA rows) plus
 * its {@link FiduciaryContext} onto the DPB-defensible DPIA structure:
 *
 * <ul>
 *   <li>The 11-section Board report structure (Rule 13(2)) + the mandatory DPIA components
 *       (§10(2)(c) + Rule 13(1)), each carrying the EXACT §/Rule citation from {@link #CITATIONS}.
 *       No citation is invented — every one is keyed to the reference doc.
 *   <li>A per-activity + overall COMPLIANCE STATUS and a GAP LIST (missing legal_basis, consent
 *       basis with no mechanism, no retention, children-data unassessed §9, cross-border
 *       unassessed §16, no DPO §10(2)(a), no grievance §13). Each gap carries its §/Rule +
 *       remediation.
 * </ul>
 *
 * <p>PII-FREE BY CONSTRUCTION: reads only activity METADATA (category labels, purpose text,
 * legal-basis enum, retention integers, counts) via a defensive allow-list projection. Pure: no
 * I/O, no clock beyond an injected {@code generatedAt}, no OpenMetadata dependencies — fully
 * unit-testable in isolation.
 */
public final class DpiaEngine {

  private DpiaEngine() {}

  // ---------------------------------------------------------------------------
  // Phase-3 substantive commencement — every §3-17 / Rule 3-15 obligation shares it.
  // Presented on each provision so the report is honest about enforceability.
  // ---------------------------------------------------------------------------
  private static final String PHASE3 = "Effective 13 May 2027 (Phase 3)";
  private static final String PHASE1 = "In force 14 Nov 2025 (Phase 1)";

  /**
   * Legal citation map — the SINGLE source of provision text. Each entry is grounded in
   * docs/legal/dpdpa-2023-dpia-reference.md. Insertion order preserved (LinkedHashMap) to match the
   * Python dict.
   */
  private static final Map<String, Map<String, String>> CITATIONS = buildCitations();

  private static Map<String, Map<String, String>> buildCitations() {
    Map<String, Map<String, String>> m = new LinkedHashMap<>();
    // --- the mandate + SDF designation ---
    m.put(
        "dpia_mandate",
        citation(
            "§10(2)(c) DPDP Act 2023; Rule 13(1)-(2) DPDP Rules 2025",
            "SDF obligation to undertake periodic DPIA",
            "A Significant Data Fiduciary must undertake a DPIA once every 12 months and submit the"
                + " report + auditor's significant observations to the Data Protection Board.",
            PHASE3));
    m.put(
        "sdf_designation",
        citation(
            "§10(1) DPDP Act 2023; Rule 12 DPDP Rules 2025",
            "Significant Data Fiduciary designation",
            "SDF status is triggered by Central Government notification assessed on"
                + " volume/sensitivity/risk; it is the gate that makes the DPIA (§10(2)(c))"
                + " mandatory.",
            PHASE3));
    // --- lawful basis (§4) ---
    m.put(
        "lawful_basis",
        citation(
            "§4(1)-(2) DPDP Act 2023",
            "Grounds for processing",
            "Every processing activity must have a lawful purpose and a legal ground: consent"
                + " (§4(1)(a)) or a legitimate use (§4(1)(b), enumerated in §7).",
            PHASE3));
    m.put(
        "consent_basis",
        citation(
            "§4(1)(a); §6(1)-(6) DPDP Act 2023; Rule 3 DPDP Rules 2025",
            "Consent as lawful ground",
            "Consent must be free, specific, informed, unconditional, unambiguous (§6(1)) and"
                + " withdrawable (§6(4)), preceded by a §5 notice in the Rule 3 itemised format; a"
                + " live consent capture + withdrawal mechanism must be evidenced.",
            PHASE3));
    m.put(
        "legitimate_use",
        citation(
            "§4(1)(b); §7(a)-(i) DPDP Act 2023",
            "Legitimate uses (non-consent ground)",
            "Non-consent processing must fall within the closed list of 9 legitimate uses in"
                + " §7(a)-(i); the DPIA must cite the specific sub-clause and justify necessity and"
                + " scope.",
            PHASE3));
    m.put(
        "notice",
        citation(
            "§5(1)-(3) DPDP Act 2023; Rule 3 DPDP Rules 2025",
            "Notice to Data Principal",
            "Before consent, an itemised notice (Rule 3) must state the personal data + purpose, the"
                + " manner of exercising rights, and the manner of complaining to the Board.",
            PHASE3));
    // --- data + retention + security ---
    m.put(
        "data_categories",
        citation(
            "§5 DPDP Act 2023; Rule 3 DPDP Rules 2025",
            "Data categories & volume",
            "The DPIA must itemise every personal-data category collected and the data-principal"
                + " categories affected.",
            PHASE3));
    m.put(
        "retention",
        citation(
            "§8(7)-(8) DPDP Act 2023; Third Schedule; Rule 8 DPDP Rules 2025",
            "Data retention & erasure",
            "A retention period must be recorded per data category (default: purpose completion, or"
                + " Third Schedule 3 years for e-commerce/gaming/social media); erasure with"
                + " 48-hour pre-erasure notice (§8(7)).",
            PHASE3));
    m.put(
        "security",
        citation(
            "§8(5) DPDP Act 2023; Rule 6(i)-(v) DPDP Rules 2025",
            "Reasonable security safeguards",
            "Rule 6 minimum controls must be documented: encryption/masking, access controls +"
                + " logs, monitoring, backups, and 1-year log retention.",
            PHASE3));
    m.put(
        "recipients",
        citation(
            "§8(1)-(2) DPDP Act 2023; §11(1)(b) DPDP Act 2023; Rule 6",
            "Recipients & processor engagement",
            "All Data Processors / third-party recipients must be listed; written contracts (§8(2))"
                + " must carry security + DPDPA compliance obligations; the Fiduciary stays liable"
                + " (§8(1)).",
            PHASE3));
    m.put(
        "children",
        citation(
            "§9(1)-(3) DPDP Act 2023; Rule 10 DPDP Rules 2025",
            "Children's data safeguards",
            "If any Data Principal is under 18: verifiable parental consent (§9(1) + Rule 10) and an"
                + " absolute ban on tracking / behavioural monitoring and targeted advertising"
                + " (§9(3)).",
            PHASE3));
    m.put(
        "cross_border",
        citation(
            "§16(1)-(2) DPDP Act 2023; Rule 15 DPDP Rules 2025",
            "Cross-border transfer",
            "Transfers outside India must be confirmed against the restricted-country list (§16(1);"
                + " none notified as of 2026-07-01) and any sectoral override (§16(2), e.g. RBI).",
            PHASE3));
    m.put(
        "special_category",
        citation(
            "§5 DPDP Act 2023; §8(4)-(5) DPDP Act 2023; Rule 6",
            "Special-category / sensitive data",
            "Where an activity handles sensitive categories, heightened security safeguards (§8(5) +"
                + " Rule 6) and a documented risk assessment (Rule 13(1)) apply.",
            PHASE3));
    m.put(
        "algorithmic",
        citation(
            "Rule 13(3) DPDP Rules 2025",
            "Algorithmic due diligence",
            "Where algorithms process personal data, the SDF must verify they are not likely to pose"
                + " a risk to Data Principal rights.",
            PHASE3));
    // --- governance / rights ---
    m.put(
        "dpo",
        citation(
            "§10(2)(a) DPDP Act 2023; §8(9) DPDP Act 2023",
            "Data Protection Officer",
            "An India-based DPO reporting to the Board of Directors must be appointed and their"
                + " contact published (§8(9)).",
            PHASE3));
    m.put(
        "auditor",
        citation(
            "§10(2)(b) DPDP Act 2023; Rule 13(2) DPDP Rules 2025",
            "Independent data auditor",
            "An independent data auditor must be appointed and their significant observations"
                + " incorporated into the Board report.",
            PHASE3));
    m.put(
        "right_access",
        citation(
            "§11(1)-(3) DPDP Act 2023; Rule 11 DPDP Rules 2025",
            "Right to access",
            "A 30/60-day access mechanism (summary of processing + recipients, first request"
                + " free/year) must be live.",
            PHASE3));
    m.put(
        "right_correction",
        citation(
            "§12(1)-(2) DPDP Act 2023",
            "Right to correction & erasure",
            "A correction / completion / erasure request mechanism must be live, with documented"
                + " exceptions.",
            PHASE3));
    m.put(
        "grievance",
        citation(
            "§13(1)-(2); §8(10) DPDP Act 2023; Rule 9 DPDP Rules 2025",
            "Right to grievance redressal",
            "A readily-available grievance mechanism with a 90-day response SLA and escalation to"
                + " the Board must be published.",
            PHASE3));
    m.put(
        "right_nominate",
        citation(
            "§14(1)-(2) DPDP Act 2023; Rule 14 DPDP Rules 2025",
            "Right to nominate",
            "A Data Principal may nominate another to exercise their rights on death or incapacity.",
            PHASE3));
    m.put(
        "breach",
        citation(
            "§8(6) DPDP Act 2023; Rule 7 DPDP Rules 2025",
            "Personal data breach notification",
            "A breach-notification capability must exist: to the Board 'without delay' + detailed"
                + " report within 72 hours, and to affected Data Principals 'without delay' in plain"
                + " language.",
            PHASE3));
    m.put(
        "board",
        citation(
            "§18, §25 DPDP Act 2023; Rule 13(2) DPDP Rules 2025",
            "Data Protection Board oversight",
            "The Board (established §18) receives the DPIA/audit report and may investigate"
                + " (§25(1)(a)) or issue corrective orders (§25(1)(c)).",
            PHASE1));
    m.put(
        "exemptions",
        citation(
            "§17(1)-(4) DPDP Act 2023",
            "Exemptions",
            "Any §17 exemption claimed must be narrowly scoped with the supporting government"
                + " notification; §17 rarely applies to private commercial fiduciaries.",
            PHASE3));
    return Collections.unmodifiableMap(m);
  }

  private static Map<String, String> citation(
      String citation, String title, String whatItAttests, String inForce) {
    Map<String, String> c = new LinkedHashMap<>();
    c.put("citation", citation);
    c.put("title", title);
    c.put("what_it_attests", whatItAttests);
    c.put("in_force", inForce);
    return c;
  }

  // Legal-basis enums the RoPA carries. A blank/unknown value is a gap.
  private static final Set<String> CONSENT_BASES =
      Collections.unmodifiableSet(new LinkedHashSet<>(Collections.singletonList("consent")));
  private static final Set<String> KNOWN_BASES =
      Collections.unmodifiableSet(
          new LinkedHashSet<>(
              Arrays.asList("consent", "legitimate_use", "legal_obligation", "vital_interest")));

  // Only these RoPA metadata fields are ever read/echoed (defence in depth vs a PII-bearing column).
  private static final List<String> ACTIVITY_METADATA_FIELDS =
      Collections.unmodifiableList(
          Arrays.asList(
              "activity_name",
              "purpose",
              "legal_basis",
              "data_categories",
              "data_subject_categories",
              "retention_period_days",
              "retention_start_event",
              "processors",
              "cross_border_transfers",
              "security_measures",
              "consent_mechanism",
              "is_special_category",
              "status"));

  // Compliance status ranking (worst wins when rolling up to the overall status).
  private static final Map<String, Integer> STATUS_ORDER = buildStatusOrder();

  private static Map<String, Integer> buildStatusOrder() {
    Map<String, Integer> m = new LinkedHashMap<>();
    m.put("compliant", 0);
    m.put("attention", 1);
    m.put("non_compliant", 2);
    return Collections.unmodifiableMap(m);
  }

  /** Return a COPY of a citation record (so a caller can never mutate the map). */
  private static Map<String, Object> citationRecord(String key) {
    Map<String, String> src = CITATIONS.get(key);
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("section", key);
    out.putAll(src);
    return out;
  }

  /**
   * Per-gap-code remediation + suggestion — powers the DPIA dashboard's Remediations tab. {@code
   * remediation} = the concrete fix; {@code suggestion} = the good-practice nudge. Keyed by the gap
   * {@code code} + the org-level codes.
   */
  private static final Map<String, Map<String, String>> REMEDIATIONS = buildRemediations();

  private static Map<String, Map<String, String>> buildRemediations() {
    Map<String, Map<String, String>> m = new LinkedHashMap<>();
    m.put(
        "missing_legal_basis",
        rem(
            "Assign a lawful ground to this activity — consent (§4(1)(a)) or a legitimate use"
                + " (§4(1)(b)/§7). Update the RoPA entry's legal_basis and publish.",
            "Prefer a specific §7 legitimate use where it genuinely applies (e.g. order fulfilment)"
                + " — it avoids a consent burden the activity doesn't need."));
    m.put(
        "missing_retention",
        rem(
            "Set a retention period + start event for this activity (§8(7)-(8)) and configure"
                + " erasure at expiry.",
            "Align to the Third Schedule class default (e.g. ~3y for e-commerce) unless a law"
                + " requires longer; document the basis."));
    m.put(
        "consent_without_mechanism",
        rem(
            "This consent-basis activity has no verification mechanism — capture consent at source"
                + " (form/cookie-banner/OTP) so each grant carries a genuine mechanism (§6).",
            "Place the at-source consent shim at the collection point so consent is free, specific"
                + " and individually opted-in — never pre-ticked."));
    m.put(
        "no_data_categories",
        rem(
            "Itemise the personal-data categories this activity collects (§5 notice + §10(2)(c)"
                + " DPIA record).",
            "Map categories from the source's actual fields via discovery, not by guesswork, so the"
                + " RoPA is defensible."));
    m.put(
        "cross_border_unassessed",
        rem(
            "Assess whether this activity's processor(s) transfer data outside India (§16); confirm"
                + " the recipient country isn't restricted and any sectoral override (e.g. RBI).",
            "Record each processor's data-residency + SCCs/equivalent; a foreign SaaS"
                + " (analytics/marketing) is usually a cross-border transfer."));
    m.put(
        "children_unassessed",
        rem(
            "Determine whether this activity processes children's data (§9); if so, implement"
                + " verifiable parental consent (Rule 10) + no tracking/targeted ads.",
            "Add an age-signal at collection so children's processing is flagged automatically, not"
                + " assessed after the fact."));
    m.put(
        "special_category_review",
        rem(
            "This activity touches sensitive/special-category data — apply heightened safeguards +"
                + " review the lawful basis and retention.",
            "Minimise: collect the sensitive field only if the purpose truly needs it;"
                + " encrypt/tokenise at rest."));
    m.put(
        "no_dpo",
        rem(
            "Appoint an India-based Data Protection Officer reporting to the Board (§10(2)(a)) and"
                + " publish their contact (§8(9)).",
            "Register the DPO in the console so the grievance + rights flows route to a real"
                + " contact."));
    m.put(
        "no_grievance",
        rem(
            "Stand up a grievance-redressal mechanism accessible to data principals (§8(10)/§13)"
                + " with a defined response SLA.",
            "Wire the My-Data grievance form to the DPO so complaints are tracked + answered within"
                + " the rule's timeline."));
    m.put(
        "no_auditor",
        rem(
            "Engage an independent data auditor (§10(2)(b)) and schedule the periodic DPIA + audit"
                + " (Rule 13).",
            "Use this DPIA report as the auditor's starting artefact — it already maps every"
                + " activity to its §/Rule."));
    m.put(
        "no_breach_process",
        rem(
            "Document a breach detection + notification process — Board within the Rule 7 timeline"
                + " + affected principals without delay (§8(6)).",
            "Prepare the breach templates now (Board report + principal notice) so the 72-hour clock"
                + " isn't spent drafting."));
    m.put(
        "children_processing_unassessed",
        rem(
            "Assess org-wide whether any activity processes children's data (§9 + Rule 10); if none,"
                + " record the determination.",
            "A documented 'we do not process children's data' finding is itself a valid, defensible"
                + " DPIA outcome."));
    return Collections.unmodifiableMap(m);
  }

  private static Map<String, String> rem(String remediation, String suggestion) {
    Map<String, String> m = new LinkedHashMap<>();
    m.put("remediation", remediation);
    m.put("suggestion", suggestion);
    return m;
  }

  /** Remediation + suggestion for a gap code (empty strings if none catalogued). */
  private static Map<String, String> remediation(String code) {
    Map<String, String> r = REMEDIATIONS.get(code);
    Map<String, String> out = new LinkedHashMap<>();
    if (r != null) {
      out.put("remediation", r.get("remediation"));
      out.put("suggestion", r.get("suggestion"));
    } else {
      out.put("remediation", "");
      out.put("suggestion", "");
    }
    return out;
  }

  // ---------------------------------------------------------------------------
  // Field coercion helpers — mirror the Python _clip / _labels / _retention_days.
  // ---------------------------------------------------------------------------

  /** Coerce to a bounded string. Length guard only (never HTML-escapes). */
  private static String clip(Object text, int limit) {
    String s = text == null ? "" : String.valueOf(text);
    return s.length() > limit ? s.substring(0, limit) : s;
  }

  private static String clip(Object text) {
    return clip(text, 1000);
  }

  /** Coerce a category-list field to a clean list of label strings (never objects). */
  @SuppressWarnings("unchecked")
  private static List<String> labels(Object val) {
    List<String> out = new ArrayList<>();
    if (val instanceof List) {
      for (Object c : (List<Object>) val) {
        if (c != null) {
          out.add(String.valueOf(c));
        }
        if (out.size() >= 64) {
          break;
        }
      }
    } else if (val instanceof Object[]) {
      for (Object c : (Object[]) val) {
        if (c != null) {
          out.add(String.valueOf(c));
        }
        if (out.size() >= 64) {
          break;
        }
      }
    }
    return out;
  }

  /** Read the integer retention period, or null if unset/unparseable (a gap). */
  private static Integer retentionDays(Map<String, Object> row) {
    Object raw = row.get("retention_period_days");
    if (raw == null) {
      return null;
    }
    // Python treats "", 0, "0" as unset (None).
    if (raw instanceof String) {
      String s = ((String) raw).trim();
      if (s.isEmpty() || "0".equals(s)) {
        return null;
      }
      try {
        int days = Integer.parseInt(s);
        return days > 0 ? days : null;
      } catch (NumberFormatException e) {
        return null;
      }
    }
    if (raw instanceof Number) {
      int days = ((Number) raw).intValue();
      return days > 0 ? days : null;
    }
    return null;
  }

  /** A consent-basis activity needs a concrete capture mechanism recorded. */
  private static boolean hasConsentMechanism(Map<String, Object> row) {
    Object mech = row.get("consent_mechanism");
    if (mech == null) {
      return false;
    }
    String s = String.valueOf(mech).trim().toLowerCase();
    return !s.isEmpty() && !"none".equals(s) && !"unknown".equals(s);
  }

  /**
   * Heuristic: does the activity's data-subject categories mention children/minors? Label-only
   * (never a subject's data). Drives the §9 'unassessed' gap.
   */
  private static boolean childrenInSubjects(Map<String, Object> row) {
    for (String s : labels(row.get("data_subject_categories"))) {
      String low = s.toLowerCase();
      if (low.contains("child")
          || low.contains("minor")
          || low.contains("under_18")
          || low.contains("under-18")) {
        return true;
      }
    }
    return false;
  }

  // ---------------------------------------------------------------------------
  // Per-activity assessment (verbatim port of _assess_activity).
  // ---------------------------------------------------------------------------

  @SuppressWarnings("unchecked")
  private static Map<String, Object> assessActivity(
      Map<String, Object> row, FiduciaryContext fiduciary) {
    Object lbRaw = row.get("legal_basis");
    String legalBasis = (lbRaw == null ? "" : String.valueOf(lbRaw)).trim().toLowerCase();
    Integer retention = retentionDays(row);
    List<String> cats = labels(row.get("data_categories"));
    List<String> subjects = labels(row.get("data_subject_categories"));

    List<Map<String, Object>> processors = new ArrayList<>();
    Object procRaw = row.get("processors");
    if (procRaw instanceof List) {
      for (Object p : (List<Object>) procRaw) {
        if (p instanceof Map) {
          processors.add((Map<String, Object>) p);
        }
      }
    }

    List<Object> xborder = new ArrayList<>();
    Object xbRaw = row.get("cross_border_transfers");
    if (xbRaw instanceof List) {
      for (Object x : (List<Object>) xbRaw) {
        if (truthy(x)) {
          xborder.add(x);
        }
      }
    }

    boolean isSpecial = truthy(row.get("is_special_category"));
    boolean isConsent = CONSENT_BASES.contains(legalBasis);

    List<Map<String, Object>> gaps = new ArrayList<>();

    // --- gap checks (each tied to the exact §/Rule from the reference doc) ---
    if (!KNOWN_BASES.contains(legalBasis)) {
      gaps.add(
          gap(
              "missing_legal_basis",
              "lawful_basis",
              "No lawful ground recorded (§4 requires consent or a §7 legitimate use)."));
    }
    if (isConsent && !hasConsentMechanism(row)) {
      gaps.add(
          gap(
              "consent_without_mechanism",
              "consent_basis",
              "Consent-basis activity has no consent capture mechanism recorded (§6 valid consent +"
                  + " §6(4) withdrawal must be evidenced)."));
    }
    if (retention == null) {
      gaps.add(
          gap(
              "missing_retention",
              "retention",
              "No retention period set (§8(7)-(8) / Third Schedule requires one per data"
                  + " category)."));
    }
    if (cats.isEmpty()) {
      gaps.add(
          gap(
              "no_data_categories",
              "data_categories",
              "No personal-data categories itemised (§5 / Rule 3)."));
    }
    if (isSpecial) {
      gaps.add(
          gap(
              "special_category_review",
              "special_category",
              "Special-category data present — confirm heightened §8(5)/Rule 6 safeguards and a"
                  + " documented risk assessment."));
    }
    if (childrenInSubjects(row) && !Boolean.TRUE.equals(fiduciary.processesChildrenData)) {
      gaps.add(
          gap(
              "children_unassessed",
              "children",
              "Data-subject categories suggest children's data but §9 verifiable parental consent /"
                  + " tracking-ban has not been assessed."));
    }
    if (!xborder.isEmpty()) {
      gaps.add(
          gap(
              "cross_border_unassessed",
              "cross_border",
              "Cross-border transfer present without a §16 recipient/sectoral assessment"
                  + " recorded."));
    }

    // --- per-activity compliance status ---
    Set<String> blocking =
        new LinkedHashSet<>(
            Arrays.asList("missing_legal_basis", "consent_without_mechanism", "missing_retention"));
    Set<String> codes = new LinkedHashSet<>();
    for (Map<String, Object> g : gaps) {
      codes.add(String.valueOf(g.get("code")));
    }
    String status;
    if (intersects(codes, blocking)) {
      status = "non_compliant";
    } else if (!gaps.isEmpty()) {
      status = "attention";
    } else {
      status = "compliant";
    }

    // --- mandatory components, each carrying its §/Rule citation ---
    Map<String, Object> components = new LinkedHashMap<>();

    Map<String, Object> processingPurpose = new LinkedHashMap<>();
    processingPurpose.put("purpose", clip(row.get("purpose")));
    processingPurpose.put("lawful_ground", legalBasis.isEmpty() ? "UNSET" : legalBasis);
    String purposeCitationKey =
        isConsent
            ? "consent_basis"
            : (!KNOWN_BASES.contains(legalBasis) ? "lawful_basis" : "legitimate_use");
    processingPurpose.put("citation", citationRecord(purposeCitationKey));
    components.put("processing_purpose", processingPurpose);

    Map<String, Object> dataCategories = new LinkedHashMap<>();
    dataCategories.put("categories", cats);
    dataCategories.put("data_subject_categories", subjects);
    dataCategories.put("special_category", isSpecial);
    dataCategories.put("citation", citationRecord("data_categories"));
    components.put("data_categories", dataCategories);

    Map<String, Object> recipients = new LinkedHashMap<>();
    recipients.put("processor_count", processors.size());
    recipients.put("citation", citationRecord("recipients"));
    components.put("recipients", recipients);

    Map<String, Object> retentionComp = new LinkedHashMap<>();
    retentionComp.put("retention_period_days", retention);
    retentionComp.put("retention_start_event", clip(row.get("retention_start_event"), 32));
    retentionComp.put("citation", citationRecord("retention"));
    components.put("retention", retentionComp);

    Map<String, Object> consentMechanism = new LinkedHashMap<>();
    consentMechanism.put("applicable", isConsent);
    consentMechanism.put("mechanism_recorded", isConsent ? hasConsentMechanism(row) : null);
    consentMechanism.put("citation", citationRecord("consent_basis"));
    components.put("consent_mechanism", consentMechanism);

    Map<String, Object> securitySafeguards = new LinkedHashMap<>();
    Object secMeasures = row.get("security_measures");
    securitySafeguards.put(
        "measures_recorded", !String.valueOf(secMeasures == null ? "" : secMeasures).trim().isEmpty());
    securitySafeguards.put("citation", citationRecord("security"));
    components.put("security_safeguards", securitySafeguards);

    Map<String, Object> crossBorder = new LinkedHashMap<>();
    crossBorder.put("transfer_present", !xborder.isEmpty());
    crossBorder.put("citation", citationRecord("cross_border"));
    components.put("cross_border", crossBorder);

    Map<String, Object> result = new LinkedHashMap<>();
    result.put("activity_name", clip(getOrDefault(row, "activity_name", "Unnamed activity"), 256));
    result.put("status", clip(row.get("status"), 32));
    result.put("lawful_ground", legalBasis.isEmpty() ? "UNSET" : legalBasis);
    result.put("compliance_status", status);
    result.put("components", components);
    result.put("gaps", gaps);
    return result;
  }

  private static Map<String, Object> gap(String code, String citationKey, String detail) {
    Map<String, Object> g = new LinkedHashMap<>();
    g.put("code", code);
    g.put("detail", detail);
    g.put("citation", citationRecord(citationKey));
    g.putAll(remediation(code));
    return g;
  }

  /** Worst-wins roll-up across all activities + org-level gaps. */
  private static String overallStatus(
      List<String> activityStatuses, List<Map<String, Object>> orgGaps) {
    int worst = 0;
    for (String st : activityStatuses) {
      Integer rank = STATUS_ORDER.get(st);
      worst = Math.max(worst, rank == null ? 1 : rank);
    }
    if (!orgGaps.isEmpty()) {
      worst = Math.max(worst, 1);
      for (Map<String, Object> g : orgGaps) {
        Object code = g.get("code");
        if ("no_dpo".equals(code) || "no_grievance".equals(code)) {
          worst = Math.max(worst, 2);
          break;
        }
      }
    }
    switch (worst) {
      case 0:
        return "compliant";
      case 2:
        return "non_compliant";
      default:
        return "attention";
    }
  }

  /**
   * Assemble the DPB-grade DPIA report (the §3 11-section Board structure). Verbatim port of {@code
   * build_dpia_report}. Deterministic and PII-free.
   *
   * @param ropaEntries this tenant's RoPA rows (metadata only; a row carries categories, never PII)
   * @param fiduciaryCtx SERVER-derived fiduciary facts (SDF flag, DPO, grievance, auditor, breach,
   *     children, consent-manager)
   * @param generatedAt injected timestamp string (may be empty)
   * @param reportingPeriod human-readable reporting period (may be empty)
   * @return a structured map: {meta, overall, sections[11], activities[]}
   */
  @SuppressWarnings("unchecked")
  public static Map<String, Object> buildDpiaReport(
      List<Map<String, Object>> ropaEntries,
      FiduciaryContext fiduciaryCtx,
      String generatedAt,
      String reportingPeriod) {

    // Assess every activity (metadata-only projection first, defence in depth).
    List<Map<String, Object>> activities = new ArrayList<>();
    for (Object rawObj : ropaEntries) {
      if (!(rawObj instanceof Map)) {
        continue;
      }
      Map<String, Object> raw = (Map<String, Object>) rawObj;
      Map<String, Object> projected = new LinkedHashMap<>();
      for (String k : ACTIVITY_METADATA_FIELDS) {
        if (raw.containsKey(k)) {
          projected.put(k, raw.get(k));
        }
      }
      activities.add(assessActivity(projected, fiduciaryCtx));
    }

    // --- organisation-level gaps (governance provisions) ---
    List<Map<String, Object>> orgGaps = new ArrayList<>();
    if (!fiduciaryCtx.hasDpo) {
      orgGaps.add(
          orgGap(
              "no_dpo",
              "No Data Protection Officer appointed (§10(2)(a) requires an India-based DPO for an"
                  + " SDF).",
              "dpo"));
    }
    if (!fiduciaryCtx.hasGrievanceMechanism) {
      orgGaps.add(
          orgGap(
              "no_grievance",
              "No grievance-redressal mechanism recorded (§13 / Rule 9, 90-day SLA).",
              "grievance"));
    }
    if (!fiduciaryCtx.hasAuditor) {
      orgGaps.add(
          orgGap(
              "no_auditor",
              "No independent data auditor recorded (§10(2)(b) / Rule 13(2)).",
              "auditor"));
    }
    if (!fiduciaryCtx.hasBreachProcess) {
      orgGaps.add(
          orgGap(
              "no_breach_process",
              "No breach-notification process recorded (§8(6) / Rule 7, 72-hour Board report).",
              "breach"));
    }
    if (fiduciaryCtx.processesChildrenData == null) {
      orgGaps.add(
          orgGap(
              "children_processing_unassessed",
              "Whether the tenant processes children's data has not been assessed (§9 / Rule 10).",
              "children"));
    }

    // Attach remediation + suggestion to each org-level gap (Remediations tab).
    for (Map<String, Object> g : orgGaps) {
      g.putAll(remediation(String.valueOf(g.get("code"))));
    }

    // --- counts (PII-free) ---
    int total = activities.size();
    Map<String, Integer> byStatus = new LinkedHashMap<>();
    byStatus.put("compliant", 0);
    byStatus.put("attention", 0);
    byStatus.put("non_compliant", 0);
    int consentActivities = 0;
    int gapTotal = 0;
    for (Map<String, Object> a : activities) {
      String cs = String.valueOf(a.get("compliance_status"));
      byStatus.put(cs, byStatus.getOrDefault(cs, 0) + 1);
      gapTotal += ((List<?>) a.get("gaps")).size();
      if (CONSENT_BASES.contains(String.valueOf(a.get("lawful_ground")))) {
        consentActivities++;
      }
    }
    gapTotal += orgGaps.size();

    List<String> activityStatuses = new ArrayList<>();
    for (Map<String, Object> a : activities) {
      activityStatuses.add(String.valueOf(a.get("compliance_status")));
    }
    String overall = overallStatus(activityStatuses, orgGaps);

    // --- the 11-section Board report structure (reference doc §3) ---
    List<Map<String, Object>> sections = new ArrayList<>();

    Map<String, Object> sec1content = new LinkedHashMap<>();
    sec1content.put("fiduciary_ref", fiduciaryCtx.fiduciaryRef);
    sec1content.put("is_significant_data_fiduciary", fiduciaryCtx.isSignificantDataFiduciary);
    sec1content.put("reporting_period", clip(reportingPeriod, 64));
    sec1content.put("overall_compliance_status", overall);
    sec1content.put("activities_assessed", total);
    sec1content.put("activities_by_status", new LinkedHashMap<>(byStatus));
    sec1content.put("total_gaps", gapTotal);
    sec1content.put("sdf_designation", citationRecord("sdf_designation"));
    sections.add(section(1, "executive_summary", "Executive Summary", "dpia_mandate", sec1content));

    Map<String, Object> sec2content = new LinkedHashMap<>();
    List<Map<String, Object>> rights = new ArrayList<>();
    rights.add(rightAssessed("access", "right_access"));
    rights.add(rightAssessed("correction_erasure", "right_correction"));
    Map<String, Object> grievRight = new LinkedHashMap<>();
    grievRight.put("right", "grievance");
    grievRight.put("implemented", fiduciaryCtx.hasGrievanceMechanism);
    grievRight.put("citation", citationRecord("grievance"));
    rights.add(grievRight);
    rights.add(rightAssessed("nominate", "right_nominate"));
    sec2content.put("rights", rights);
    sections.add(
        section(
            2,
            "data_principal_rights",
            "Data Principal Rights Assessment",
            "dpia_mandate",
            sec2content));

    Map<String, Object> sec3content = new LinkedHashMap<>();
    sec3content.put("activities_assessed", total);
    sec3content.put("consent_basis_activities", consentActivities);
    sec3content.put(
        "note",
        "Per-activity purpose, lawful ground, data categories, recipients and retention are"
            + " itemised under 'activities'.");
    sections.add(section(3, "processing_audit", "Processing Audit", "lawful_basis", sec3content));

    Map<String, Object> sec4content = new LinkedHashMap<>();
    sec4content.put("breach_process_recorded", fiduciaryCtx.hasBreachProcess);
    sec4content.put("breach_citation", citationRecord("breach"));
    sec4content.put("security_citation", citationRecord("security"));
    sections.add(
        section(
            4,
            "security_breach",
            "Security & Breach Readiness Assessment",
            "security",
            sec4content));

    Map<String, Object> sec5content = new LinkedHashMap<>();
    sec5content.put("consent_basis_activities", consentActivities);
    sec5content.put("consent_manager_registered", fiduciaryCtx.hasConsentManager);
    sec5content.put("notice_citation", citationRecord("notice"));
    sections.add(
        section(5, "consent_notice", "Consent & Notice Compliance", "consent_basis", sec5content));

    Map<String, Object> sec6content = new LinkedHashMap<>();
    sec6content.put("processes_children_data", fiduciaryCtx.processesChildrenData);
    sec6content.put(
        "note",
        "§9 verifiable parental consent + §9(3) tracking/ad prohibitions apply if any Data"
            + " Principal is under 18.");
    sections.add(
        section(6, "children_data", "Children's Data Processing", "children", sec6content));

    int activitiesWithTransfers = 0;
    for (Map<String, Object> a : activities) {
      Map<String, Object> comps = (Map<String, Object>) a.get("components");
      Map<String, Object> cb = (Map<String, Object>) comps.get("cross_border");
      if (Boolean.TRUE.equals(cb.get("transfer_present"))) {
        activitiesWithTransfers++;
      }
    }
    Map<String, Object> sec7content = new LinkedHashMap<>();
    sec7content.put("activities_with_transfers", activitiesWithTransfers);
    sec7content.put(
        "restricted_list_status",
        "No restricted-country list notified as of 2026-07-01 (reference doc §11).");
    sections.add(
        section(
            7, "cross_border", "Cross-Border Transfer Risk Assessment", "cross_border", sec7content));

    Map<String, Object> sec8content = new LinkedHashMap<>();
    sec8content.put(
        "note",
        "Rule 13(3) due-diligence applies where algorithms process personal data; assess per"
            + " deployed system.");
    sections.add(
        section(8, "algorithmic", "Algorithmic Risk Assessment", "algorithmic", sec8content));

    Map<String, Object> sec9content = new LinkedHashMap<>();
    sec9content.put("has_dpo", fiduciaryCtx.hasDpo);
    sec9content.put("dpo_citation", citationRecord("dpo"));
    sec9content.put("has_grievance_mechanism", fiduciaryCtx.hasGrievanceMechanism);
    sec9content.put("grievance_citation", citationRecord("grievance"));
    sections.add(
        section(9, "grievance_dpo", "Grievance & DPO Effectiveness", "dpo", sec9content));

    Map<String, Object> sec10content = new LinkedHashMap<>();
    sec10content.put("has_auditor", fiduciaryCtx.hasAuditor);
    sec10content.put(
        "note",
        "§10(2)(b) auditor's significant observations are incorporated here (Rule 13(2)); attach"
            + " the auditor summary on submission.");
    sections.add(
        section(10, "auditor_findings", "Independent Auditor Findings", "auditor", sec10content));

    Map<String, Object> sec11content = new LinkedHashMap<>();
    sec11content.put("overall_compliance_status", overall);
    sec11content.put("total_gaps", gapTotal);
    sec11content.put("organisation_gaps", orgGaps);
    sec11content.put(
        "note",
        "Material gaps + remediation actions; the Board (§18/§25) reviews these under Rule"
            + " 13(2).");
    sections.add(
        section(
            11, "significant_observations", "Significant Observations", "board", sec11content));

    // --- assemble ---
    Map<String, Object> meta = new LinkedHashMap<>();
    meta.put("report_type", "DPIA");
    meta.put("framework", "DPDP Act 2023 + DPDP Rules 2025");
    meta.put("generated_at", clip(generatedAt, 64));
    meta.put("reporting_period", clip(reportingPeriod, 64));
    meta.put("fiduciary_ref", fiduciaryCtx.fiduciaryRef);
    meta.put("is_significant_data_fiduciary", fiduciaryCtx.isSignificantDataFiduciary);
    meta.put("mandate", citationRecord("dpia_mandate"));
    meta.put(
        "in_force_note",
        "Substantive DPDP obligations (§3-17, Rule 3/5-15, Third Schedule) take effect 13 May 2027"
            + " (Phase 3). Gaps before that date are preparedness gaps, not enforced breaches"
            + " (reference doc §5, §15).");

    Map<String, Object> overallMap = new LinkedHashMap<>();
    overallMap.put("compliance_status", overall);
    overallMap.put("activities_assessed", total);
    overallMap.put("activities_by_status", new LinkedHashMap<>(byStatus));
    overallMap.put("total_gaps", gapTotal);
    overallMap.put("organisation_gaps", orgGaps);

    Map<String, Object> report = new LinkedHashMap<>();
    report.put("meta", meta);
    report.put("overall", overallMap);
    report.put("sections", sections);
    report.put("activities", activities);
    return report;
  }

  /** Convenience overload matching the Python default-arg call sites (empty timestamps). */
  public static Map<String, Object> buildDpiaReport(
      List<Map<String, Object>> ropaEntries, FiduciaryContext fiduciaryCtx) {
    return buildDpiaReport(ropaEntries, fiduciaryCtx, "", "");
  }

  private static Map<String, Object> orgGap(String code, String detail, String citationKey) {
    Map<String, Object> g = new LinkedHashMap<>();
    g.put("code", code);
    g.put("detail", detail);
    g.put("citation", citationRecord(citationKey));
    return g;
  }

  private static Map<String, Object> section(
      int n, String id, String title, String citationKey, Map<String, Object> content) {
    Map<String, Object> s = new LinkedHashMap<>();
    s.put("n", n);
    s.put("id", id);
    s.put("title", title);
    s.put("citation", citationRecord(citationKey));
    s.put("content", content);
    return s;
  }

  private static Map<String, Object> rightAssessed(String right, String citationKey) {
    Map<String, Object> r = new LinkedHashMap<>();
    r.put("right", right);
    r.put("assessed", true);
    r.put("citation", citationRecord(citationKey));
    return r;
  }

  // --- small helpers replicating Python truthiness / dict.get semantics ---

  private static boolean truthy(Object v) {
    if (v == null) {
      return false;
    }
    if (v instanceof Boolean) {
      return (Boolean) v;
    }
    if (v instanceof String) {
      return !((String) v).isEmpty();
    }
    if (v instanceof Number) {
      return ((Number) v).doubleValue() != 0.0;
    }
    if (v instanceof List) {
      return !((List<?>) v).isEmpty();
    }
    if (v instanceof Map) {
      return !((Map<?, ?>) v).isEmpty();
    }
    return true;
  }

  private static boolean intersects(Set<String> a, Set<String> b) {
    for (String s : a) {
      if (b.contains(s)) {
        return true;
      }
    }
    return false;
  }

  private static Object getOrDefault(Map<String, Object> row, String key, Object def) {
    Object v = row.get(key);
    return v == null ? def : v;
  }
}
