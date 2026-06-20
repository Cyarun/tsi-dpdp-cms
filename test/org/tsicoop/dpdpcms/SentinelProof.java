package org.tsicoop.dpdpcms;

import org.tsicoop.dpdpcms.framework.PasswordHasher;
import java.security.SecureRandom;

/**
 * vAIb-q3g5 — standalone, dependency-free PROOF that the passwordless
 * UNUSABLE_PASSWORD_HASH sentinel carried by the AUTO-CREATED Wix-owner operator
 * can NEVER be used to password-login.
 *
 * Lives OUTSIDE src/ so the WAR build (sourceDirectory=src) never ships it.
 *
 * It mirrors Operator.generateUnusablePasswordHash() EXACTLY (a BCrypt of a
 * discarded SecureRandom value) and drives the SAME PasswordHasher.verifyPassword
 * that handleLogin uses (Operator.java handleLogin), proving:
 *   1. the sentinel is a well-formed "$2" BCrypt (so verifyPassword never throws
 *      "Invalid salt version" -> no 500), and
 *   2. verifyPassword / checkPassword return FALSE for every candidate password.
 *
 * Run (from apps/tsi-dpdp-cms, JDK 15+):
 *   javac --release 15 -cp "JBCRYPT_JAR" -d /tmp/out \
 *       src/org/tsicoop/dpdpcms/framework/PasswordHasher.java \
 *       test/org/tsicoop/dpdpcms/SentinelProof.java
 *   java -cp "/tmp/out:JBCRYPT_JAR" org.tsicoop.dpdpcms.SentinelProof
 */
public class SentinelProof {

    /** EXACT mirror of Operator.generateUnusablePasswordHash(). */
    static String generateUnusablePasswordHash() {
        byte[] rnd = new byte[32];
        new SecureRandom().nextBytes(rnd);
        String throwaway = java.util.Base64.getEncoder().encodeToString(rnd);
        return new PasswordHasher().hashPassword(throwaway);
    }

    public static void main(String[] args) {
        PasswordHasher ph = new PasswordHasher();
        String sentinel = generateUnusablePasswordHash();
        int failures = 0;

        // 1) sentinel is a well-formed BCrypt ("$2"): verifyPassword won't throw.
        if (!sentinel.startsWith("$2")) {
            System.out.println("FAIL: sentinel is not a $2 BCrypt hash");
            failures++;
        } else {
            System.out.println("OK: sentinel is a $2 BCrypt hash (len=" + sentinel.length() + ")");
        }

        // 2) handleLogin uses verifyPassword -> must be false (no match, no throw).
        String[] candidates = {
            "", " ", "password", "Admin@12345!", "P@ssw0rdP@ssw0rd",
            "Site Owner (Wix)", "owner@example.com", "12345678",
            "Aa1!Aa1!Aa1!", sentinel /* even the hash text itself */
        };
        boolean batteryClean = true;
        for (String c : candidates) {
            boolean matched;
            try {
                matched = ph.verifyPassword(c, sentinel);
            } catch (RuntimeException e) {
                System.out.println("FAIL: verifyPassword THREW for candidate (len="
                        + c.length() + "): " + e);
                failures++; batteryClean = false; continue;
            }
            if (matched) {
                System.out.println("FAIL: verifyPassword MATCHED for candidate: [" + c + "]");
                failures++; batteryClean = false;
            }
        }
        if (batteryClean) {
            System.out.println("OK: verifyPassword rejected all " + candidates.length
                    + " candidates (no match, no throw) — password-login REJECTS the sentinel");
        }

        // 3) checkPassword (recovery path style) likewise no-matches cleanly.
        for (String c : candidates) {
            if (ph.checkPassword(c, sentinel)) {
                System.out.println("FAIL: checkPassword MATCHED for candidate: [" + c + "]");
                failures++;
            }
        }

        // 4) Control: a real password matches ITS OWN hash (harness is genuine)
        //    and does NOT match the sentinel.
        String realPwd = "Real@Password123!";
        String realHash = ph.hashPassword(realPwd);
        if (!ph.verifyPassword(realPwd, realHash)) {
            System.out.println("FAIL: control — real password did not match its own hash");
            failures++;
        } else {
            System.out.println("OK: control — a real password matches its own BCrypt hash");
        }
        if (ph.verifyPassword(realPwd, sentinel)) {
            System.out.println("FAIL: real password matched the sentinel");
            failures++;
        }

        System.out.println(failures == 0
                ? "\nALL SENTINEL PROOFS PASSED"
                : "\n" + failures + " PROOF(S) FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }
}
