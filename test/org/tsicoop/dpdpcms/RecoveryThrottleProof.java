package org.tsicoop.dpdpcms;

import org.tsicoop.dpdpcms.framework.LoginRateLimiter;
import org.tsicoop.dpdpcms.util.PassphraseGenerator;

/**
 * vAIb-83bu — standalone, dependency-free PROOF for the recovery-endpoint hardening
 * (security re-review, FINDING 1). Lives OUTSIDE src/ so the WAR build never ships it.
 *
 * Proves the two authoritative fixes to the un-throttled, low-entropy recovery path:
 *
 *   (1) THROTTLE: LoginRateLimiter — the SAME limiter handleResetViaRecovery and
 *       handleVerifyRecoveryKey now call at the top — allows exactly MAX_ATTEMPTS (5)
 *       within the window and BLOCKS the 6th, keyed on the composite IP+email key the
 *       recovery handlers use. So the un-throttled brute-force oracle is closed.
 *
 *   (2) ENTROPY: PassphraseGenerator now draws from the EFF large wordlist (7,772 words),
 *       so a 5-word phrase carries ~64.6 bits (5 * log2(7772)) — up from the old ~33 bits
 *       of the 96-word sample list — putting a guess far out of reach even before the
 *       throttle. Also proves the phrase FORMAT is unchanged (5 hyphen-separated words).
 *
 * Run:  javac test/.../RecoveryThrottleProof.java (+ the two classes) && java ... RecoveryThrottleProof
 */
public class RecoveryThrottleProof {

    public static void main(String[] args) {
        int failures = 0;

        // ---- (1) THROTTLE ---------------------------------------------------------------
        // Mirror the recovery handlers' key shape exactly: IP + "|recovery|" + email. A unique
        // email per run keeps this test independent of any other bucket state in the JVM.
        String key = "203.0.113.7|recovery|proof-" + System.nanoTime() + "@tenant.example";
        int allowed = 0;
        for (int i = 0; i < 5; i++) {
            if (LoginRateLimiter.isAllowed(key)) allowed++;
        }
        boolean sixthBlocked = !LoginRateLimiter.isAllowed(key);
        if (allowed == 5 && sixthBlocked) {
            System.out.println("OK: recovery throttle — first 5 attempts allowed, 6th BLOCKED (429 path)");
        } else {
            System.out.println("FAIL: recovery throttle — allowed=" + allowed
                    + " (expected 5), sixthBlocked=" + sixthBlocked + " (expected true)");
            failures++;
        }

        // A DIFFERENT email (same IP) has its OWN bucket — one targeted email being exhausted
        // does not lock out an unrelated operator, and vice-versa. Proves the per-email keying.
        String otherKey = "203.0.113.7|recovery|other-" + System.nanoTime() + "@tenant.example";
        if (LoginRateLimiter.isAllowed(otherKey)) {
            System.out.println("OK: recovery throttle — a different email has an independent bucket");
        } else {
            System.out.println("FAIL: recovery throttle — a fresh email/key was blocked unexpectedly");
            failures++;
        }

        // ---- (2) ENTROPY ----------------------------------------------------------------
        int words = PassphraseGenerator.wordListSize();
        double bits5 = 5.0 * (Math.log(words) / Math.log(2.0));
        // The EFF large wordlist is 7,776 lines; we keep pure-alpha distinct words (7,772),
        // so require a large list AND >= 60 bits for a 5-word phrase (comfortably clears the
        // ~50-bit floor the reviewer set; the EFF list gives ~64.6 bits).
        if (words >= 7000) {
            System.out.println("OK: passphrase wordlist size = " + words + " (EFF large wordlist)");
        } else {
            System.out.println("FAIL: passphrase wordlist too small = " + words + " (want >= 7000)");
            failures++;
        }
        if (bits5 >= 60.0) {
            System.out.printf("OK: 5-word phrase entropy = %.2f bits (>= 60)%n", bits5);
        } else {
            System.out.printf("FAIL: 5-word phrase entropy = %.2f bits (< 60)%n", bits5);
            failures++;
        }

        // FORMAT unchanged: default generate() is 5 hyphen-separated lowercase words.
        String phrase = PassphraseGenerator.generate();
        String[] parts = phrase.split("-");
        boolean fmtOk = parts.length == 5;
        for (String p : parts) {
            if (p.isEmpty() || !p.chars().allMatch(Character::isLetter)) { fmtOk = false; break; }
        }
        if (fmtOk) {
            System.out.println("OK: passphrase format unchanged — 5 hyphen-separated words");
        } else {
            System.out.println("FAIL: passphrase format changed — [" + phrase + "]");
            failures++;
        }

        System.out.println(failures == 0
                ? "\nALL RECOVERY-THROTTLE PROOFS PASSED"
                : "\n" + failures + " PROOF(S) FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }
}
