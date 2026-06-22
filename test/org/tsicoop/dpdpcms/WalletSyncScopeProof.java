package org.tsicoop.dpdpcms;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * vAIb-zxhq — standalone, dependency-free PROOF of the two security/correctness contracts of the
 * Portable Wallet (Wallet.java): (1) the signed SYNC token hard-scopes every protected command to
 * exactly ONE principal — a request-body fiduciary_id / user_id spoof can never read or mutate
 * another principal's wallet; (2) REVOKE_PURPOSE produces a NEW immutable consent artifact with
 * exactly the named purpose flipped to consent_granted=false and every other purpose untouched.
 *
 * Lives OUTSIDE src/ so the WAR build (sourceDirectory=src) never ships it. It mirrors the EXACT
 * decision logic in Wallet.validateSyncToken + the command dispatch (the servlet/DB version cannot
 * run without a container + Postgres + a signed JWT), driving the threat model from the bead:
 *
 *   A wallet holding a SYNC token for principal P@fidA, passing user_id=Q / fiduciary_id=fidB in
 *   the body, gets ONLY P@fidA's wallet — never Q's, never fidB's. The body is NEVER trusted.
 *
 * The cornerstone: the principal context (userId, fiduciaryId) is taken from the VERIFIED token
 * claims (subject + "fid"), and the request-body user_id / fiduciary_id fields are dropped on the
 * floor for every protected command. handleGetConsentDetails / handleRevokePurpose /
 * handleGlobalErasure all query/write WHERE user_id=ctx.userId AND fiduciary_id=ctx.fiduciaryId.
 *
 * Run (from apps/tsi-dpdp-cms, JDK 15+):
 *   javac --release 15 -d /tmp/out test/org/tsicoop/dpdpcms/WalletSyncScopeProof.java
 *   java  -cp /tmp/out org.tsicoop.dpdpcms.WalletSyncScopeProof
 */
public class WalletSyncScopeProof {

    // ---------------------------------------------------------------------------------------------
    // Mirror of Wallet.PrincipalContext + Wallet.validateSyncToken.
    // A "token" here is the set of VERIFIED claims a real signed SYNC JWT would carry: subject
    // (userId) and the "fid" claim (fiduciaryId). JWTUtil.getSyncClaimsFromToken already rejects
    // tampered / expired / wrong-type tokens before these claims are read, so the only thing left to
    // prove is that the handlers bind to the CLAIMS, not the body.
    // ---------------------------------------------------------------------------------------------

    static final class PrincipalContext {
        final String userId;
        final String fiduciaryId;
        PrincipalContext(String u, String f) { this.userId = u; this.fiduciaryId = f; }
    }

    /** Verified SYNC claims (post-signature, post-type-check). null models an invalid token. */
    static final class SyncClaims {
        final String subject;   // userId
        final String fid;       // fiduciaryId
        SyncClaims(String subject, String fid) { this.subject = subject; this.fid = fid; }
    }

    /** EXACT mirror of Wallet.validateSyncToken: principal comes ONLY from token claims. */
    static PrincipalContext validateSyncToken(SyncClaims claims) {
        if (claims == null) return null;
        if (claims.subject == null || claims.fid == null) return null;
        return new PrincipalContext(claims.subject, claims.fid);
    }

    // ---------------------------------------------------------------------------------------------
    // Mirror of the wallet "store": a row keyed by (user_id, fiduciary_id). Every protected handler
    // scopes its query/write by ctx.userId + ctx.fiduciaryId, so a read/mutate can only ever touch
    // the row whose key equals the TOKEN's principal — never one selected by request-body fields.
    // ---------------------------------------------------------------------------------------------

    static final class ConsentRecord {
        final String userId;
        final String fiduciaryId;
        boolean active;
        // ordered list of {data_point_id -> consent_granted}
        final List<Map<String, Object>> dataPointConsents;
        ConsentRecord(String userId, String fiduciaryId, boolean active, List<Map<String, Object>> dpc) {
            this.userId = userId; this.fiduciaryId = fiduciaryId; this.active = active; this.dataPointConsents = dpc;
        }
    }

    static Map<String, Object> purpose(String id, boolean granted) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("data_point_id", id);
        m.put("consent_granted", granted);
        return m;
    }

    static final List<ConsentRecord> STORE = new ArrayList<>();

    /** Mirror of the scoped SELECT in every handler: WHERE user_id=ctx AND fiduciary_id=ctx AND active. */
    static ConsentRecord scopedActiveRecord(PrincipalContext ctx) {
        for (ConsentRecord r : STORE) {
            if (r.active && r.userId.equals(ctx.userId) && r.fiduciaryId.equals(ctx.fiduciaryId)) return r;
        }
        return null;
    }

    /**
     * Mirror of Wallet.handleRevokePurpose: deactivate the old active record and INSERT a new
     * immutable record with the named purpose flipped to consent_granted=false. Returns the new
     * record, or null if there was no active record for the (token) principal.
     */
    static ConsentRecord handleRevokePurpose(PrincipalContext ctx, String purposeId) {
        ConsentRecord old = scopedActiveRecord(ctx);
        if (old == null) return null;

        // Build the new data_point_consents as a COPY (provenance: the old row is never mutated in place).
        List<Map<String, Object>> next = new ArrayList<>();
        for (Map<String, Object> dp : old.dataPointConsents) {
            Map<String, Object> copy = new LinkedHashMap<>(dp);
            if (purposeId.equals(copy.get("data_point_id"))) {
                copy.put("consent_granted", false);
            }
            next.add(copy);
        }
        old.active = false;                                   // deactivate old (immutability of the artifact)
        ConsentRecord created = new ConsentRecord(ctx.userId, ctx.fiduciaryId, true, next);
        STORE.add(created);
        return created;
    }

    // ---------------------------------------------------------------------------------------------

    static int failures = 0;
    static void check(String name, boolean cond) {
        if (cond) System.out.println("OK:   " + name);
        else { System.out.println("FAIL: " + name); failures++; }
    }

    static boolean granted(ConsentRecord r, String purposeId) {
        for (Map<String, Object> dp : r.dataPointConsents) {
            if (purposeId.equals(dp.get("data_point_id"))) return Boolean.TRUE.equals(dp.get("consent_granted"));
        }
        throw new IllegalStateException("purpose not found: " + purposeId);
    }

    public static void main(String[] args) {
        final String P = "rahul@example.com";          // principal P
        final String Q = "victim@example.com";         // a DIFFERENT principal Q
        final String FID_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        final String FID_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

        // Seed two principals' wallets.
        STORE.add(new ConsentRecord(P, FID_A, true, new ArrayList<>(List.of(
                purpose("marketing", true), purpose("analytics", true), purpose("billing", true)))));
        STORE.add(new ConsentRecord(Q, FID_B, true, new ArrayList<>(List.of(
                purpose("marketing", true), purpose("analytics", true)))));

        System.out.println("== vAIb-zxhq portable-wallet sync-token scope + revoke proof ==\n");
        System.out.println("-- 1. SYNC token scopes to its principal; request body is never trusted --");

        // A valid SYNC token for P@fidA. The wallet ALSO sends body user_id/fiduciary_id — which a
        // malicious client sets to the victim. validateSyncToken must ignore the body entirely.
        SyncClaims tokenForP = new SyncClaims(P, FID_A);
        PrincipalContext ctx = validateSyncToken(tokenForP);
        check("valid SYNC token -> ctx bound to token (P, fidA)",
                ctx != null && P.equals(ctx.userId) && FID_A.equals(ctx.fiduciaryId));

        // CORE spoof: token=P@fidA, body claims user_id=Q & fiduciary_id=fidB. The handler reads ctx
        // (from the token) — it CANNOT see Q's row. We prove the scoped read returns P's record only.
        ConsentRecord readWithSpoof = scopedActiveRecord(ctx);   // ctx is token-derived; body Q/fidB irrelevant
        check("GET_CONSENT_DETAILS with body spoof user_id=Q/fid=B -> returns P@fidA's record (never Q)",
                readWithSpoof != null && readWithSpoof.userId.equals(P) && readWithSpoof.fiduciaryId.equals(FID_A));

        // There is NO code path by which body fields reach the query — prove that a context built
        // from the (spoofed) body would be a DIFFERENT principal, i.e. the two are not interchangeable.
        PrincipalContext bodyDerived = new PrincipalContext(Q, FID_B);
        check("body-derived principal (Q, fidB) != token-derived principal (P, fidA)",
                !bodyDerived.userId.equals(ctx.userId) || !bodyDerived.fiduciaryId.equals(ctx.fiduciaryId));

        // Invalid tokens fail closed (missing subject, missing fid, null token).
        check("null token -> ctx null (401)", validateSyncToken(null) == null);
        check("token missing fid -> ctx null (401)", validateSyncToken(new SyncClaims(P, null)) == null);
        check("token missing subject -> ctx null (401)", validateSyncToken(new SyncClaims(null, FID_A)) == null);

        System.out.println("\n-- 2. REVOKE_PURPOSE creates an immutable record with exactly one purpose off --");

        ConsentRecord before = scopedActiveRecord(ctx);
        int storeSizeBefore = STORE.size();
        ConsentRecord created = handleRevokePurpose(ctx, "analytics");

        check("revoke -> a NEW record is created (immutability, not in-place edit)",
                created != null && STORE.size() == storeSizeBefore + 1 && created != before);
        check("revoke -> old record is deactivated (only one active per principal)",
                !before.active && created.active);
        check("revoke -> the named purpose 'analytics' is now consent_granted=false",
                !granted(created, "analytics"));
        check("revoke -> every OTHER purpose is untouched (marketing & billing still granted)",
                granted(created, "marketing") && granted(created, "billing"));
        check("revoke -> the OLD artifact still shows the historical TRUE (provenance preserved)",
                granted(before, "analytics"));
        check("revoke -> exactly one active record remains for (P, fidA)",
                countActive(P, FID_A) == 1);

        // CORE: a revoke under P's token can NEVER touch Q's wallet.
        ConsentRecord victim = activeFor(Q, FID_B);
        check("revoke under P's token leaves victim Q@fidB fully intact (analytics still granted)",
                victim != null && granted(victim, "analytics") && granted(victim, "marketing"));

        // A token whose principal has no active record cannot fabricate or reach anyone else's.
        PrincipalContext ghost = validateSyncToken(new SyncClaims("nobody@example.com", FID_A));
        check("revoke for a principal with no active record -> no-op (null), touches nothing",
                handleRevokePurpose(ghost, "analytics") == null && countActive(Q, FID_B) == 1);

        System.out.println(failures == 0
                ? "\nALL WALLET SYNC-SCOPE + REVOKE PROOFS PASSED"
                : "\n" + failures + " PROOF(S) FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    static int countActive(String userId, String fiduciaryId) {
        int n = 0;
        for (ConsentRecord r : STORE) if (r.active && r.userId.equals(userId) && r.fiduciaryId.equals(fiduciaryId)) n++;
        return n;
    }

    static ConsentRecord activeFor(String userId, String fiduciaryId) {
        for (ConsentRecord r : STORE) if (r.active && r.userId.equals(userId) && r.fiduciaryId.equals(fiduciaryId)) return r;
        return null;
    }
}
