package org.tsicoop.dpdpcms;

import org.tsicoop.dpdpcms.service.v1.Operator;
import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.UUID;

/**
 * vAIb-q3g5 integration test: drives the REAL Operator.autoCreateOwnerOperator /
 * selectActiveOperator (private, via reflection) against a real Postgres, proving:
 *   T1 ACTIVE tenant w/ NO operator      -> creates EXACTLY ONE passwordless ADMIN, binds it
 *   T2 second call (idempotent)          -> finds same operator, NO duplicate
 *   T3 INACTIVE fiduciary                -> creates NOTHING, returns null (fail-closed)
 *   T4 unknown fiduciary id              -> creates NOTHING, returns null (fail-closed)
 *   T5 created operator is passwordless  -> password_hash is "$2" sentinel, recovery_key_hash NULL
 *   T6 synthetic email when fiduciary has no contact email
 */
public class AutoCreateIT {
    static final String URL = "jdbc:postgresql://localhost:55433/cmstest";
    static int failures = 0;

    static void check(boolean cond, String msg) {
        System.out.println((cond ? "OK  : " : "FAIL: ") + msg);
        if (!cond) failures++;
    }

    static int operatorCount(Connection c, UUID fid) throws Exception {
        try (PreparedStatement ps = c.prepareStatement(
                "SELECT count(*) FROM operators WHERE fiduciary_id = ?")) {
            ps.setObject(1, fid);
            try (ResultSet r = ps.executeQuery()) { r.next(); return r.getInt(1); }
        }
    }

    public static void main(String[] args) throws Exception {
        Class.forName("org.postgresql.Driver");
        Operator op = new Operator();

        Method autoCreate = Operator.class.getDeclaredMethod(
                "autoCreateOwnerOperator", Connection.class, UUID.class, String.class);
        autoCreate.setAccessible(true);

        UUID activeWithEmail = UUID.fromString("9fc18087-0000-0000-0000-000000000001");
        UUID activeNoEmail   = UUID.fromString("9fc18087-0000-0000-0000-000000000002");
        UUID inactive        = UUID.fromString("9fc18087-0000-0000-0000-000000000003");
        UUID unknown         = UUID.fromString("9fc18087-0000-0000-0000-0000000000ff");

        try (Connection c = DriverManager.getConnection(URL, "postgres", "test")) {

            // T1: ACTIVE tenant, no operator -> create one ADMIN and bind.
            check(operatorCount(c, activeWithEmail) == 0, "T1 precondition: tenant has 0 operators");
            Object bound1 = autoCreate.invoke(op, c, activeWithEmail, "admin");
            check(bound1 != null, "T1 auto-create returned a bound operator");
            check(operatorCount(c, activeWithEmail) == 1, "T1 exactly ONE operator now exists");

            // Inspect the created row.
            try (PreparedStatement ps = c.prepareStatement(
                    "SELECT name, role, status, password_hash, recovery_key_hash, " +
                    "pgp_sym_decrypt(decode(email_enc,'base64'),'testkey123') AS email " +
                    "FROM operators WHERE fiduciary_id = ?")) {
                ps.setObject(1, activeWithEmail);
                try (ResultSet r = ps.executeQuery()) {
                    r.next();
                    check("ADMIN".equals(r.getString("role")), "T5 role = ADMIN");
                    check("ACTIVE".equals(r.getString("status")), "T5 status = ACTIVE");
                    String ph = r.getString("password_hash");
                    check(ph != null && ph.startsWith("$2"), "T5 password_hash is a $2 BCrypt sentinel (not null, not plaintext)");
                    check(r.getString("recovery_key_hash") == null, "T5 recovery_key_hash is NULL");
                    String email = r.getString("email");
                    check("owner@nailtalk.io".equals(email), "T5 email derived from fiduciary contact = " + email);
                    check(r.getString("name").contains(activeWithEmail.toString()), "T5 name is globally-unique (embeds fiduciary UUID)");
                }
            }

            // T2: idempotency — call again, must NOT create a duplicate.
            Object bound2 = autoCreate.invoke(op, c, activeWithEmail, "admin");
            check(bound2 != null, "T2 second call still returns a bound operator");
            check(operatorCount(c, activeWithEmail) == 1, "T2 still exactly ONE operator (idempotent, no duplicate)");

            // T3: INACTIVE fiduciary -> no create, null.
            Object boundInactive = autoCreate.invoke(op, c, inactive, "admin");
            check(boundInactive == null, "T3 INACTIVE fiduciary -> returns null (no bind)");
            check(operatorCount(c, inactive) == 0, "T3 INACTIVE fiduciary -> NO operator created (fail-closed)");

            // T4: unknown fiduciary -> no create, null.
            Object boundUnknown = autoCreate.invoke(op, c, unknown, "admin");
            check(boundUnknown == null, "T4 unknown fiduciary -> returns null");
            check(operatorCount(c, unknown) == 0, "T4 unknown fiduciary -> NO operator created");

            // T6: ACTIVE tenant without contact email -> synthetic owner+<fid>@<domain>.
            Object boundNoEmail = autoCreate.invoke(op, c, activeNoEmail, "admin");
            check(boundNoEmail != null, "T6 no-email tenant still auto-creates");
            check(operatorCount(c, activeNoEmail) == 1, "T6 exactly one operator for no-email tenant");
            try (PreparedStatement ps = c.prepareStatement(
                    "SELECT pgp_sym_decrypt(decode(email_enc,'base64'),'testkey123') AS email FROM operators WHERE fiduciary_id = ?")) {
                ps.setObject(1, activeNoEmail);
                try (ResultSet r = ps.executeQuery()) {
                    r.next();
                    String email = r.getString("email");
                    check(email.equals("owner+" + activeNoEmail + "@noemail.example"),
                            "T6 synthetic email = " + email);
                }
            }
        }

        System.out.println(failures == 0 ? "\nALL INTEGRATION CHECKS PASSED" : "\n" + failures + " CHECK(S) FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }
}
