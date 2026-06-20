package org.tsicoop.dpdpcms;

import org.tsicoop.dpdpcms.service.v1.Operator;
import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * vAIb-q3g5 concurrency proof: N threads each call the REAL
 * Operator.autoCreateOwnerOperator on the SAME fresh ACTIVE tenant at once.
 * Expectation: exactly ONE operator row is created (the 23505 unique-violation
 * branch re-SELECTs and binds), every thread gets a non-null bound operator,
 * and NO thread errors.
 */
public class RaceIT {
    static final String URL = "jdbc:postgresql://localhost:55433/cmstest";

    public static void main(String[] args) throws Exception {
        Class.forName("org.postgresql.Driver");
        Operator op = new Operator();
        Method autoCreate = Operator.class.getDeclaredMethod(
                "autoCreateOwnerOperator", Connection.class, UUID.class, String.class);
        autoCreate.setAccessible(true);

        UUID fid = UUID.fromString("9fc18087-0000-0000-0000-0000000000aa");
        final int N = 8;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(N);
        AtomicInteger bound = new AtomicInteger(0);
        AtomicInteger errors = new AtomicInteger(0);

        for (int i = 0; i < N; i++) {
            new Thread(() -> {
                try (Connection c = DriverManager.getConnection(URL, "postgres", "test")) {
                    start.await();
                    Object r = autoCreate.invoke(op, c, fid, "admin");
                    if (r != null) bound.incrementAndGet();
                    else System.out.println("WARN: a thread got null bind");
                } catch (Throwable t) {
                    errors.incrementAndGet();
                    System.out.println("THREAD ERROR: " + t.getCause());
                } finally {
                    done.countDown();
                }
            }).start();
        }
        start.countDown();   // release all threads at once
        done.await();

        int count;
        try (Connection c = DriverManager.getConnection(URL, "postgres", "test");
             PreparedStatement ps = c.prepareStatement("SELECT count(*) FROM operators WHERE fiduciary_id = ?")) {
            ps.setObject(1, fid);
            try (ResultSet rs = ps.executeQuery()) { rs.next(); count = rs.getInt(1); }
        }

        int failures = 0;
        if (errors.get() != 0) { System.out.println("FAIL: " + errors.get() + " thread error(s)"); failures++; }
        else System.out.println("OK  : no thread errors across " + N + " concurrent callers");
        if (bound.get() != N) { System.out.println("FAIL: only " + bound.get() + "/" + N + " threads bound an operator"); failures++; }
        else System.out.println("OK  : all " + N + " concurrent callers bound an operator");
        if (count != 1) { System.out.println("FAIL: " + count + " operator rows created (expected exactly 1)"); failures++; }
        else System.out.println("OK  : exactly ONE operator row created under concurrency (idempotent, no duplicate)");

        System.out.println(failures == 0 ? "\nRACE PROOF PASSED" : "\n" + failures + " RACE CHECK(S) FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }
}
