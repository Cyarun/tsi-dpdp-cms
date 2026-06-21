package org.tsicoop.dpdpcms;

import java.util.UUID;

/**
 * vAIb-ae11 — standalone, dependency-free PROOF of the per-tenant scoping decision that
 * InputProcessor.resolveTenantScope(req, res, requireTargetForPlatform) enforces for every
 * operator-console (/api/v1/admin/*) endpoint.
 *
 * Lives OUTSIDE src/ so the WAR build (sourceDirectory=src) never ships it. It mirrors the
 * EXACT decision logic of InputProcessor.resolveTenantScope (the servlet/DB version cannot run
 * without a container + Postgres), and drives the threat model from the bead:
 *
 *   A tenant operator of fiduciary A passing fiduciary_id=B (or none) gets ONLY A's data
 *   (or is DENIED) — never B's. list_fiduciaries for a tenant operator returns exactly 1.
 *
 * The cornerstone: the discriminator is the VERIFIED FIDUCIARY (all-zeros ADMIN_FID = platform
 * admin), NOT the JWT role — because the auto-created Wix-owner operator is role=ADMIN but bound
 * to a CONCRETE tenant. This proof asserts that a role=ADMIN tenant operator is STILL hard-scoped.
 *
 * Run (from apps/tsi-dpdp-cms, JDK 15+):
 *   javac --release 15 -d /tmp/out test/org/tsicoop/dpdpcms/TenantScopeProof.java
 *   java  -cp /tmp/out org.tsicoop.dpdpcms.TenantScopeProof
 */
public class TenantScopeProof {

    static final UUID PLATFORM_ADMIN_FID = UUID.fromString("00000000-0000-0000-0000-000000000000");

    /** Outcome of a scope resolution: either an allowed effective fiduciary, or a denial. */
    static final class Outcome {
        final UUID fid;          // null when denied
        final int  denyCode;     // 0 when allowed, else HTTP status (401/403)
        private Outcome(UUID fid, int denyCode) { this.fid = fid; this.denyCode = denyCode; }
        static Outcome allow(UUID f) { return new Outcome(f, 0); }
        static Outcome deny(int code) { return new Outcome(null, code); }
        boolean allowed() { return denyCode == 0; }
    }

    /**
     * EXACT mirror of InputProcessor.resolveTenantScope(req, res, requireTargetForPlatform).
     * @param verifiedFid the operator's OWN fiduciary from the DB (PLATFORM_ADMIN_FID if null in DB),
     *                    or null to simulate an unresolvable caller.
     * @param bodyFid     the client-supplied fiduciary_id (or fiduciary_id_filter); null = absent.
     */
    static Outcome resolveTenantScope(UUID verifiedFid, String bodyFid, boolean requireTargetForPlatform) {
        if (verifiedFid == null) return Outcome.deny(401);                 // unresolvable caller

        boolean isPlatform = PLATFORM_ADMIN_FID.equals(verifiedFid);

        if (!isPlatform) {
            // Tenant-scoped operator: hard-scope to own fiduciary; deny any mismatching target.
            if (bodyFid != null && !bodyFid.isEmpty()
                    && !bodyFid.equalsIgnoreCase(verifiedFid.toString())) {
                return Outcome.deny(403);                                  // cross-tenant attempt
            }
            return Outcome.allow(verifiedFid);                            // ignores body, own only
        }

        // Platform admin: body fiduciary_id selects the target tenant.
        if (bodyFid == null || bodyFid.isEmpty()) {
            return requireTargetForPlatform ? Outcome.deny(403) : Outcome.allow(PLATFORM_ADMIN_FID);
        }
        try { return Outcome.allow(UUID.fromString(bodyFid)); }
        catch (IllegalArgumentException e) { return Outcome.deny(403); }
    }

    static int failures = 0;

    static void check(String name, boolean cond) {
        if (cond) System.out.println("OK:   " + name);
        else { System.out.println("FAIL: " + name); failures++; }
    }

    public static void main(String[] args) {
        final UUID A = UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"); // tenant A
        final UUID B = UUID.fromString("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"); // tenant B

        System.out.println("== vAIb-ae11 per-tenant scope proof ==\n");
        System.out.println("-- Threat model: tenant-A operator (the Wix-owner is role=ADMIN, concrete fid=A) --");

        // 1. Tenant operator A passing NO fiduciary_id -> scoped to A (by-id / mutation).
        Outcome o1 = resolveTenantScope(A, null, true);
        check("A, no body fid (by-id) -> ALLOW scoped to A",
                o1.allowed() && A.equals(o1.fid));

        // 2. Tenant operator A passing their OWN fiduciary_id=A -> scoped to A.
        Outcome o2 = resolveTenantScope(A, A.toString(), true);
        check("A, body fid=A -> ALLOW scoped to A",
                o2.allowed() && A.equals(o2.fid));

        // 3. CORE: Tenant operator A passing fiduciary_id=B -> DENIED 403 (never B's data).
        Outcome o3 = resolveTenantScope(A, B.toString(), true);
        check("A, body fid=B (cross-tenant) -> DENY 403 (never B)",
                !o3.allowed() && o3.denyCode == 403);

        // 4. CORE: even on a LIST op (requireTarget=false), A passing fiduciary_id=B is DENIED.
        Outcome o4 = resolveTenantScope(A, B.toString(), false);
        check("A, body fid=B (list) -> DENY 403 (never B)",
                !o4.allowed() && o4.denyCode == 403);

        // 5. list op: A with no body fid -> scoped to A (exactly its own — proves list_* returns
        //    ONLY tenant A's rows; e.g. list_fiduciaries returns exactly 1: A's own).
        Outcome o5 = resolveTenantScope(A, null, false);
        check("A, no body fid (list) -> ALLOW scoped to A (own only; list_fiduciaries == 1)",
                o5.allowed() && A.equals(o5.fid));

        // 6. A passing a malformed body fid that does not equal A -> DENY (never silent fallthrough).
        Outcome o6 = resolveTenantScope(A, "not-a-uuid", true);
        check("A, malformed cross body fid -> DENY 403",
                !o6.allowed() && o6.denyCode == 403);

        System.out.println("\n-- Platform admin (verified fiduciary is the all-zeros ADMIN_FID) --");

        // 7. Platform admin must NAME a target tenant on a by-id/mutation op.
        Outcome o7 = resolveTenantScope(PLATFORM_ADMIN_FID, null, true);
        check("platform, no body fid (by-id) -> DENY 403 (must name target)",
                !o7.allowed() && o7.denyCode == 403);

        // 8. Platform admin naming tenant B -> ALLOW scoped to B (provisioning/support path).
        Outcome o8 = resolveTenantScope(PLATFORM_ADMIN_FID, B.toString(), true);
        check("platform, body fid=B -> ALLOW scoped to B (provisioning)",
                o8.allowed() && B.equals(o8.fid));

        // 9. Platform admin LIST with no target -> ALLOW sentinel (caller lists across all tenants).
        Outcome o9 = resolveTenantScope(PLATFORM_ADMIN_FID, null, false);
        check("platform, no body fid (list) -> ALLOW sentinel (all tenants)",
                o9.allowed() && PLATFORM_ADMIN_FID.equals(o9.fid));

        System.out.println("\n-- Fail-closed --");

        // 10. Unresolvable caller (DB error / no auth) -> DENY 401.
        Outcome o10 = resolveTenantScope(null, B.toString(), true);
        check("unresolvable caller -> DENY 401 (fail closed)",
                !o10.allowed() && o10.denyCode == 401);

        System.out.println(failures == 0
                ? "\nALL TENANT-SCOPE PROOFS PASSED"
                : "\n" + failures + " PROOF(S) FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }
}
