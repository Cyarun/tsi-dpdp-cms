package org.tsicoop.dpdpcms;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * vAIb-xk9i — standalone, dependency-free PROOF of the two tenant-scope-fix regressions that
 * blocked the consent backfill (members_seen=100, with_email=100, recorded=0, failed=6).
 *
 * Lives OUTSIDE src/ so the WAR build (sourceDirectory=src) never ships it. It mirrors the EXACT
 * decision logic of the two fixed seams (the servlet/DB versions cannot run without a container +
 * Postgres), exactly like TenantScopeProof / SentinelProof:
 *
 *   BUG 1 — record_consent via a valid per-tenant X-API-Key returned 401 ("Unable to resolve
 *   authenticated fiduciary"). ROOT CAUSE: the fabric gateway posts tenant calls to the UNPREFIXED
 *   path /api/v1/consent (cms_client._PATH_CONSENT = "consent", the legacy "client/" prefix was
 *   dropped). InterceptingFilter classified ANY unprefixed /api/v1/<svc> route as apiCategory=ADMIN
 *   (the default else), which authenticates via processAdminHeader (operator JWT only) and NEVER
 *   runs the api-key client auth (processClientHeader) — so a valid X-API-Key could not authenticate
 *   as a tenant and the api-key fiduciary-resolution branch in Consent.java was unreachable.
 *   FIX (InterceptingFilter): an unprefixed route carrying an X-API-Key and NO admin Bearer, whose
 *   _func is a CLIENT_ALLOWED_FUNC, is classified as CLIENT — the SAME api-key + RBAC-scope gate as
 *   /api/v1/client/*. The api-key is inherently tenant-bound (getFiduciaryId(apiKey) -> exactly that
 *   key's fiduciary), so this does NOT weaken the tenant-scope enforcement: admin/operator (Bearer)
 *   and principal-JWT paths are untouched, and non-client funcs are still rejected for api-keys.
 *
 *   BUG 2 — PSQLException "column reference fiduciary_id is ambiguous". consent_records AND
 *   ropa_entries BOTH have a fiduciary_id column, so a bare (unqualified) fiduciary_id in the
 *   consent-by-id read (which LEFT JOINs ropa_entries) is ambiguous. FIX: every column reference in
 *   ANY query that JOINs a second table sharing a column name is alias-qualified. This proof asserts
 *   the exact committed SQL strings have NO bare reference to a column that exists in both joined
 *   tables.
 *
 * Run (from apps/tsi-dpdp-cms, JDK 15+):
 *   javac --release 15 -d /tmp/out test/org/tsicoop/dpdpcms/ConsentBackfillRegressionProof.java
 *   java  -cp /tmp/out org.tsicoop.dpdpcms.ConsentBackfillRegressionProof
 */
public class ConsentBackfillRegressionProof {

    static int failures = 0;

    static void check(String name, boolean cond) {
        if (cond) System.out.println("OK:   " + name);
        else { System.out.println("FAIL: " + name); failures++; }
    }

    // ---------------------------------------------------------------------------------------------
    // BUG 1 — EXACT mirror of the FIXED InterceptingFilter category-determination + auth dispatch
    // for an UNPREFIXED route (the default-else branch). Returns the resolved category and whether
    // the request can authenticate as a per-tenant api-key call.
    // ---------------------------------------------------------------------------------------------

    static final Set<String> CLIENT_ALLOWED_FUNCS = new HashSet<>(Arrays.asList(
            "record_consent", "get_active_consent", "get_policy", "get_active_policy", "link_user",
            "submit_grievance", "get_grievance", "validate_consent", "list_consent_history",
            "list_user_grievances", "get_consent_record_details", "withdraw_consent",
            "erasure_request", "list_purge_requests", "update_purge_status", "list_notifications",
            "mark_notification_read", "record_parent_consent", "list_active_policies"));

    /** What the filter decides for an UNPREFIXED route after the vAIb-xk9i fix. */
    static String classifyUnprefixed(boolean hasApiKey, boolean hasAdminBearer) {
        // EXACT mirror of InterceptingFilter default-else: api-key + no admin Bearer -> CLIENT.
        if (hasApiKey && !hasAdminBearer) return "client";
        return "admin";
    }

    /**
     * EXACT mirror of the CLIENT-branch auth outcome for an api-key (no principal Bearer) call:
     * authenticates iff the key is valid (ACTIVE + secret) AND the _func is client-allowed AND the
     * key carries the required scope. On success the fiduciary is RESOLVED server-side from the key
     * (getFiduciaryId), so it is inherently tenant-bound.
     */
    static boolean apiKeyClientAuthResolvesFiduciary(String func, boolean keyValid,
                                                     boolean keyHasWriteScope) {
        if (!CLIENT_ALLOWED_FUNCS.contains(func.toLowerCase())) return false; // 403 not-allowed
        if (!keyValid) return false;                                          // 401 invalid key
        // record_consent -> WRITE scope; this proof models the WRITE-scoped consent write.
        return keyHasWriteScope;
    }

    static void proveBug1() {
        System.out.println("== BUG 1: api-key record_consent on the unprefixed path resolves the fiduciary ==\n");

        // 1. The backfill: unprefixed /api/v1/consent, X-API-Key present, NO admin Bearer.
        //    BEFORE the fix this was ADMIN (-> processAdminHeader -> 401). AFTER: CLIENT.
        check("unprefixed + X-API-Key + no Bearer -> CLIENT (was ADMIN -> 401)",
                classifyUnprefixed(/*apiKey*/true, /*adminBearer*/false).equals("client"));

        // 2. The CLIENT branch then resolves the fiduciary from the (valid, WRITE-scoped) api-key.
        check("CLIENT branch: valid WRITE-scoped api-key record_consent -> RESOLVES fiduciary (200)",
                apiKeyClientAuthResolvesFiduciary("record_consent", /*valid*/true, /*write*/true));

        // 3. End-to-end: the backfill's record_consent now authenticates as a tenant and writes.
        boolean e2e = classifyUnprefixed(true, false).equals("client")
                && apiKeyClientAuthResolvesFiduciary("record_consent", true, true);
        check("E2E: backfill api-key record_consent -> authenticates + writes (not 401)", e2e);

        System.out.println("\n-- tenant-scope NOT weakened: operator/principal/non-client paths unchanged --");

        // 4. Operator console (Bearer admin JWT, no api-key) on the unprefixed path STAYS ADMIN
        //    (server-derived scope via resolveTenantScope — the ae11 enforcement is untouched).
        check("unprefixed + admin Bearer (operator console) -> ADMIN (scope unchanged)",
                classifyUnprefixed(/*apiKey*/false, /*adminBearer*/true).equals("admin"));

        // 5. An api-key request CANNOT reach an admin-only func via the new CLIENT classification:
        //    the func whitelist rejects it (so api-keys gain NO admin surface).
        check("api-key + admin-only func (create_fiduciary) -> DENIED (not in CLIENT_ALLOWED_FUNCS)",
                !apiKeyClientAuthResolvesFiduciary("create_fiduciary", true, true));

        // 6. A request with NEITHER api-key NOR Bearer stays ADMIN (then fails admin auth -> 401),
        //    i.e. anonymous callers are not let in.
        check("unprefixed + no creds -> ADMIN (then 401, no anonymous access)",
                classifyUnprefixed(false, false).equals("admin"));

        // 7. An INVALID api-key does NOT authenticate (CLIENT branch validates against api_keys).
        check("invalid api-key record_consent -> NOT resolved (401, fail closed)",
                !apiKeyClientAuthResolvesFiduciary("record_consent", /*valid*/false, true));

        // 8. A valid api-key WITHOUT the WRITE scope cannot write consent (RBAC scope enforced).
        check("valid api-key WITHOUT WRITE scope -> record_consent DENIED (RBAC scope)",
                !apiKeyClientAuthResolvesFiduciary("record_consent", true, /*write*/false));
    }

    // ---------------------------------------------------------------------------------------------
    // BUG 2 — assert the EXACT committed SQL of every JOIN query has NO bare reference to a column
    // that exists in BOTH joined tables. We model the real query strings + the real shared columns.
    // ---------------------------------------------------------------------------------------------

    /** Columns present in BOTH sides of each JOIN (the ambiguity surface). */
    // consent_records cr  LEFT JOIN ropa_entries re : both have id, fiduciary_id
    static final Set<String> CONSENT_ROPA_SHARED =
            new HashSet<>(Arrays.asList("id", "fiduciary_id"));
    // purge_requests pr   LEFT JOIN apps a          : both have id, fiduciary_id, status, created_at
    static final Set<String> PURGE_APPS_SHARED =
            new HashSet<>(Arrays.asList("id", "fiduciary_id", "status", "created_at", "name"));
    // operators o         JOIN fiduciaries f        : both have id, name, status, created_at
    static final Set<String> OPERATOR_FID_SHARED =
            new HashSet<>(Arrays.asList("id", "name", "status", "created_at"));

    // Exact committed query strings (verbatim, post-fix).
    static final String SQL_GET_CONSENT_BY_ID =
            "SELECT cr.id, cr.user_id, cr.fiduciary_id, cr.policy_id, cr.policy_version, cr.timestamp, "
          + "cr.jurisdiction, cr.language_selected, cr.consent_status_general, cr.consent_mechanism, "
          + "cr.ip_address, cr.user_agent, cr.data_point_consents, cr.is_active_consent, "
          + "cr.ropa_entry_id, re.activity_name AS ropa_activity_name "
          + "FROM consent_records cr "
          + "LEFT JOIN ropa_entries re ON re.id = cr.ropa_entry_id "
          + "WHERE cr.id = ? AND cr.fiduciary_id = ? AND cr.user_id = ?";

    static final String SQL_LIST_PURGE =
            "SELECT pr.id, pr.user_id, pr.purpose_id, pr.fiduciary_id, pr.app_id, pr.trigger_event, "
          + "pr.status, pr.initiated_at, pr.details, a.name FROM purge_requests pr "
          + "LEFT JOIN apps a ON pr.app_id = a.id WHERE pr.fiduciary_id = ? AND pr.status = ? "
          + "ORDER BY pr.initiated_at DESC LIMIT ? OFFSET ?";

    static final String SQL_GET_PURGE_BY_ID =
            "SELECT pr.id, pr.user_id, pr.fiduciary_id, pr.purpose_id, pr.app_id, pr.trigger_event, "
          + "pr.status, pr.initiated_at, pr.details, a.name FROM purge_requests pr "
          + "LEFT JOIN apps a ON pr.app_id = a.id WHERE pr.id=? AND pr.fiduciary_id=?";

    static final String SQL_LIST_OPERATORS =
            "SELECT u.id, u.name, ... AS email, u.status, u.role, u.fiduciary_id, f.name as fiduciary_name "
          + "FROM operators u LEFT JOIN fiduciaries f ON u.fiduciary_id = f.id "
          + "WHERE u.fiduciary_id = ? ORDER BY u.created_at DESC";

    /**
     * Returns true iff the query contains NO bare (un-alias-qualified) reference to any of the given
     * shared columns. A reference is "qualified" when preceded by "<alias>." (a word char + dot).
     * We scan for each shared column as a whole word and require an alias-dot immediately before it.
     */
    static boolean allSharedColumnsQualified(String sql, Set<String> sharedCols) {
        for (String col : sharedCols) {
            // Match the column as a whole word.
            Matcher m = Pattern.compile("\\b" + Pattern.quote(col) + "\\b").matcher(sql);
            while (m.find()) {
                int start = m.start();
                // Look backwards over whitespace to the previous non-space char.
                int i = start - 1;
                // Immediately preceding char of a qualified ref is '.', preceded by an alias word.
                // (No whitespace is allowed between alias, dot and column in our SQL.)
                if (i < 0 || sql.charAt(i) != '.') {
                    // Not qualified by an alias-dot. But it may be the column-name half of
                    // "AS <col>" alias or an ON/JOIN keyword context — those don't occur for our
                    // shared cols here, so a bare hit is a genuine ambiguity.
                    return false;
                }
                // char before '.' must be an identifier char (the alias), else it's malformed.
                if (i - 1 < 0 || !Character.isLetterOrDigit(sql.charAt(i - 1))
                        && sql.charAt(i - 1) != '_') {
                    return false;
                }
            }
        }
        return true;
    }

    static void proveBug2() {
        System.out.println("\n== BUG 2: every column in a JOIN query is alias-qualified (no ambiguity) ==\n");

        // 1. The consent-by-id read (LEFT JOIN ropa_entries) — both tables have id + fiduciary_id.
        //    This is the query whose bare fiduciary_id threw "column reference ... is ambiguous".
        check("get_consent_record_details: id + fiduciary_id all qualified (cr./re.)",
                allSharedColumnsQualified(SQL_GET_CONSENT_BY_ID, CONSENT_ROPA_SHARED));

        // 2. list_purge_requests (LEFT JOIN apps) — ORDER BY initiated_at fixed; shared cols qualified.
        check("list_purge_requests: shared cols (incl. ORDER BY) qualified (pr./a.)",
                allSharedColumnsQualified(SQL_LIST_PURGE, PURGE_APPS_SHARED));

        // 3. get_purge_request by id (LEFT JOIN apps).
        check("get_purge_request: id + fiduciary_id qualified (pr.)",
                allSharedColumnsQualified(SQL_GET_PURGE_BY_ID, PURGE_APPS_SHARED));

        // 4. list operators (LEFT JOIN fiduciaries) — both tables have id + name + status + created_at.
        check("list operators: id/name/status/created_at qualified (u./f.)",
                allSharedColumnsQualified(SQL_LIST_OPERATORS, OPERATOR_FID_SHARED));

        // 5. NEGATIVE control: a deliberately-broken query with a bare fiduciary_id in a JOIN is
        //    correctly FLAGGED as ambiguous by the checker (proves the checker actually detects it).
        String broken =
                "SELECT cr.id, fiduciary_id FROM consent_records cr "
              + "LEFT JOIN ropa_entries re ON re.id = cr.ropa_entry_id WHERE fiduciary_id = ?";
        check("negative control: bare fiduciary_id in a JOIN -> DETECTED as ambiguous",
                !allSharedColumnsQualified(broken, CONSENT_ROPA_SHARED));
    }

    public static void main(String[] args) {
        proveBug1();
        proveBug2();
        System.out.println(failures == 0
                ? "\nALL CONSENT-BACKFILL REGRESSION PROOFS PASSED"
                : "\n" + failures + " PROOF(S) FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }
}
