package org.tsicoop.dpdpcms;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * vAIb-4u20 — standalone, dependency-free PROOF of DPDP §9 verifiable parental consent gating.
 *
 * Lives OUTSIDE src/ so the WAR build (sourceDirectory=src) never ships it, mirroring
 * ConsentBackfillRegressionProof / TenantScopeProof / SentinelProof: the real servlet seams need a
 * container + Postgres + the fabric secret to run, so this mirrors the EXACT decision logic of the
 * two new seams in Consent.java:
 *
 *   SEAM 1 — enforceMinorPurposeGating (Consent.java): an UNVERIFIED MINOR may grant MANDATORY
 *   purposes only; every OPTIONAL purpose they tried to grant is forced consent_granted=false.
 *   A VERIFIED minor (or one with a verification_log_id on the same request) and any ADULT pass
 *   through unchanged.
 *
 *   SEAM 2 — handleRecordParentalVerification AUTH GATE (Consent.java): record_parent_consent
 *   requires the fabric->CMS shared-secret proof (PARENTAL_VERIFIER_SECRET). FAIL CLOSED: a null
 *   secret, an empty/absent proof, or a wrong proof is rejected (constant-time compare).
 *
 * Build & run (matches the sibling proof):
 *   javac --release 15 -d /tmp/out test/org/tsicoop/dpdpcms/ParentalConsentGatingProof.java
 *   java  -cp /tmp/out org.tsicoop.dpdpcms.ParentalConsentGatingProof
 */
public class ParentalConsentGatingProof {

    static int failures = 0;

    static void check(String name, boolean cond) {
        if (cond) System.out.println("OK:   " + name);
        else { System.out.println("FAIL: " + name); failures++; }
    }

    // ---- mirrored constants (Constants.java) ----
    static final String AGE_ADULT = "ADULT";
    static final String AGE_MINOR = "MINOR";
    static final String VERIFIED = "VERIFIED";
    static final String NOT_VERIFIED = "NOT_VERIFIED";

    // A minimal data-point-consent: purpose id + whether the principal tried to grant it.
    static final class DPC {
        final String purposeId; boolean granted;
        DPC(String purposeId, boolean granted) { this.purposeId = purposeId; this.granted = granted; }
    }

    /**
     * EXACT mirror of Consent.enforceMinorPurposeGating: returns the consents after gating.
     * mandatoryPurposeIds models the policy's is_mandatory_for_service=true purpose ids.
     */
    static DPC[] enforceMinorPurposeGating(String ageCategory, String verificationStatus,
                                           boolean verificationLogIdOnRequest,
                                           Set<String> mandatoryPurposeIds, DPC[] consents) {
        boolean isMinor = AGE_MINOR.equalsIgnoreCase(ageCategory);
        boolean isVerified = VERIFIED.equalsIgnoreCase(verificationStatus) || verificationLogIdOnRequest;
        if (!isMinor || isVerified) return consents; // adults + verified minors untouched
        for (DPC c : consents) {
            boolean mandatory = c.purposeId != null && mandatoryPurposeIds.contains(c.purposeId);
            if (!mandatory && c.granted) c.granted = false; // strip optional grants
        }
        return consents;
    }

    /**
     * EXACT mirror of the handleRecordParentalVerification auth gate: returns true iff the call is
     * trusted (== HTTP 201 path). FAIL CLOSED on null secret / empty / mismatched proof.
     */
    static boolean parentalAuthGatePasses(byte[] secret, String verifierOtp) {
        return secret != null
                && verifierOtp != null && !verifierOtp.isEmpty()
                && MessageDigest.isEqual(secret, verifierOtp.getBytes(StandardCharsets.UTF_8));
    }

    static boolean grantedFor(DPC[] consents, String purposeId) {
        for (DPC c : consents) if (purposeId.equals(c.purposeId)) return c.granted;
        return false;
    }

    static void proveAgeGating() {
        System.out.println("== SEAM 1: DPDP §9 minor optional-purpose gating ==\n");

        Set<String> mandatory = new HashSet<>(Arrays.asList("purpose_account_management"));

        // CORE REQUIREMENT: a MINOR who is NOT verified canNOT grant an OPTIONAL purpose,
        // but mandatory purposes still go through.
        DPC[] minorUnverified = new DPC[]{
                new DPC("purpose_account_management", true),  // mandatory
                new DPC("purpose_marketing", true),           // optional
                new DPC("purpose_analytics", true)            // optional
        };
        enforceMinorPurposeGating(AGE_MINOR, NOT_VERIFIED, false, mandatory, minorUnverified);
        check("unverified minor: MANDATORY purpose stays granted",
                grantedFor(minorUnverified, "purpose_account_management"));
        check("unverified minor: OPTIONAL purpose_marketing is BLOCKED",
                !grantedFor(minorUnverified, "purpose_marketing"));
        check("unverified minor: OPTIONAL purpose_analytics is BLOCKED",
                !grantedFor(minorUnverified, "purpose_analytics"));

        // CORE REQUIREMENT: guardian verification UNBLOCKS optional purposes for the same minor.
        DPC[] minorVerified = new DPC[]{
                new DPC("purpose_account_management", true),
                new DPC("purpose_marketing", true),
                new DPC("purpose_analytics", true)
        };
        enforceMinorPurposeGating(AGE_MINOR, VERIFIED, false, mandatory, minorVerified);
        check("VERIFIED minor: OPTIONAL purpose_marketing is now ALLOWED",
                grantedFor(minorVerified, "purpose_marketing"));
        check("VERIFIED minor: OPTIONAL purpose_analytics is now ALLOWED",
                grantedFor(minorVerified, "purpose_analytics"));

        // Same-request verification_log_id (atomic verify+grant) also unblocks.
        DPC[] minorWithLog = new DPC[]{ new DPC("purpose_marketing", true) };
        enforceMinorPurposeGating(AGE_MINOR, NOT_VERIFIED, true, mandatory, minorWithLog);
        check("minor with verification_log_id on the SAME request: OPTIONAL allowed",
                grantedFor(minorWithLog, "purpose_marketing"));

        // Adults are never gated.
        DPC[] adult = new DPC[]{ new DPC("purpose_marketing", true) };
        enforceMinorPurposeGating(AGE_ADULT, NOT_VERIFIED, false, mandatory, adult);
        check("ADULT: OPTIONAL purpose passes through untouched",
                grantedFor(adult, "purpose_marketing"));

        // FAIL-CLOSED on unparseable policy: empty mandatory set -> unverified minor's optional
        // grants are ALL stripped (we never silently grant when we cannot prove mandatory).
        DPC[] minorNoPolicy = new DPC[]{ new DPC("purpose_account_management", true) };
        enforceMinorPurposeGating(AGE_MINOR, NOT_VERIFIED, false, new HashSet<>(), minorNoPolicy);
        check("unparseable policy (no mandatory set): unverified minor grants ALL stripped (fail-closed)",
                !grantedFor(minorNoPolicy, "purpose_account_management"));
    }

    static void proveAuthGate() {
        System.out.println("\n== SEAM 2: record_parent_consent fabric-secret auth gate (fail closed) ==\n");

        byte[] secret = "fabric-shared-secret-xyz".getBytes(StandardCharsets.UTF_8);

        check("correct verifier_otp -> gate PASSES (records VERIFIED parental consent)",
                parentalAuthGatePasses(secret, "fabric-shared-secret-xyz"));
        check("wrong verifier_otp -> gate REJECTS (401)",
                !parentalAuthGatePasses(secret, "guessed-value"));
        check("empty verifier_otp -> gate REJECTS (401)",
                !parentalAuthGatePasses(secret, ""));
        check("null verifier_otp -> gate REJECTS (401)",
                !parentalAuthGatePasses(secret, null));
        check("UNSET secret (env missing) -> gate REJECTS EVERYTHING (fail closed)",
                !parentalAuthGatePasses(null, "fabric-shared-secret-xyz"));
    }

    /** EXACT mirror of the link_user §9 guard: a client-supplied VERIFIED is downgraded. */
    static String linkUserVerificationStatus(String clientSupplied) {
        if (VERIFIED.equalsIgnoreCase(clientSupplied)) return NOT_VERIFIED;
        return clientSupplied;
    }

    static void proveLinkUserGuard() {
        System.out.println("\n== SEAM 3: link_user cannot self-assert VERIFIED (no OTP-gate bypass) ==\n");
        check("link_user supplies VERIFIED -> DOWNGRADED to NOT_VERIFIED",
                NOT_VERIFIED.equals(linkUserVerificationStatus(VERIFIED)));
        check("link_user supplies NOT_VERIFIED -> stays NOT_VERIFIED",
                NOT_VERIFIED.equals(linkUserVerificationStatus(NOT_VERIFIED)));

        // The bypass that this closes: an unverified minor linked-as-VERIFIED would have had optional
        // purposes UNBLOCKED. After the downgrade, the gate still blocks them.
        Set<String> mandatory = new HashSet<>(Arrays.asList("purpose_account_management"));
        String gatedStatus = linkUserVerificationStatus(VERIFIED); // attacker tried VERIFIED
        DPC[] consents = new DPC[]{ new DPC("purpose_marketing", true) };
        enforceMinorPurposeGating(AGE_MINOR, gatedStatus, false, mandatory, consents);
        check("minor linked with a forged VERIFIED: OPTIONAL still BLOCKED (bypass closed)",
                !grantedFor(consents, "purpose_marketing"));
    }

    public static void main(String[] args) {
        proveAgeGating();
        proveAuthGate();
        proveLinkUserGuard();
        System.out.println(failures == 0
                ? "\nALL PARENTAL-CONSENT GATING PROOFS PASSED"
                : "\n" + failures + " PROOF(S) FAILED");
        if (failures != 0) System.exit(1);
    }
}
