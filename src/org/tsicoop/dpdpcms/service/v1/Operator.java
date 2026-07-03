package org.tsicoop.dpdpcms.service.v1;

import org.tsicoop.dpdpcms.framework.*;
import org.tsicoop.dpdpcms.util.Constants;
import org.tsicoop.dpdpcms.util.PassphraseGenerator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Operator class for managing CMS backend users and recovery keys.
 * Refactored to include loggedInUserId and standardized ADMIN audit logging after cleanup.
 */
public class Operator implements Action {

    private final PasswordHasher passwordHasher = new PasswordHasher();
    private static final UUID ADMIN_FID_UUID = UUID.fromString("00000000-0000-0000-0000-000000000000");

    /**
     * Shared secret that gates the PUBLIC operator_session endpoint (unified Wix
     * identity — vAIb-pigk). EXACT MIRROR of Principal.PRINCIPAL_LOGIN_SECRET.
     *
     * UNIFIED IDENTITY (user-decided): Wix owns ALL login. The owner authenticates
     * on the Wix dashboard; the fabric (gateway) VERIFIES the Wix-signed instance
     * (HMAC over APP_SECRET + known-instance allowlist), resolves the tenant's
     * fiduciary_id from OpenBao, and ONLY THEN calls operator_session passing THIS
     * shared secret. The CMS therefore trusts the call iff the caller proves it
     * knows the secret — exactly the principal_login pattern. The CMS /api/v1/admin/
     * operator PASSWORD login is BYPASSED for the console handoff; no operator types
     * a CMS password (it stays usable as a break-glass fallback only).
     *
     * Read from OPERATOR_LOGIN_SECRET — same discipline as JWT_SECRET / PRINCIPAL_
     * LOGIN_SECRET: NEVER hardcoded, NEVER logged. FAIL CLOSED: unset/empty => null
     * => EVERY operator_session is rejected (no default — a default would re-open a
     * passwordless mint to anyone). Constant-time compare (MessageDigest.isEqual).
     * SCOPED + DISTINCT from PRINCIPAL_LOGIN_SECRET so a leak of one cannot forge
     * the other (a principal secret must never mint an operator/admin session).
     */
    private static final byte[] OPERATOR_LOGIN_SECRET = loadOperatorLoginSecret();

    private static byte[] loadOperatorLoginSecret() {
        String secret = System.getenv("OPERATOR_LOGIN_SECRET");
        if (secret == null || secret.trim().isEmpty()) {
            // FAIL CLOSED: no secret configured -> reject all operator_session. Do
            // NOT throw at class-load (that would also break the password login +
            // user-management funcs); the null is checked per-request and rejects.
            System.err.println("SECURITY: OPERATOR_LOGIN_SECRET is not set — "
                    + "operator_session (Wix-owner console handoff) is DISABLED "
                    + "(fail closed). Set it to the value provisioned in OpenBao "
                    + "(vaib/cms/operator_login_secret).");
            return null;
        }
        return secret.trim().getBytes(StandardCharsets.UTF_8);
    }

    private static final Pattern PASSWORD_PATTERN =
            Pattern.compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+])[A-Za-z\\d!@#$%^&*()_+]{12,}$");
    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}$");

    /**
     * UNUSABLE password-hash sentinel for the AUTO-CREATED Wix owner operator
     * (vAIb-q3g5). The owner has NO CMS password — Wix owns login (unified
     * identity); the owner reaches the console ONLY via the secret-gated
     * operator_session mint, NEVER via the password path.
     *
     * Why a real BCrypt hash of a one-time random value (NOT null, NOT a literal):
     *  - It is a well-formed "$2"-prefixed BCrypt string, so handleLogin's
     *    PasswordHasher.verifyPassword (a raw BCrypt.checkpw) returns false
     *    CLEANLY for ANY supplied password — it never throws "Invalid salt
     *    version" (which a non-BCrypt literal would, surfacing as a 500).
     *  - It also satisfies PasswordHasher.checkPassword's "$2" guard (used on the
     *    recovery path) so that path likewise no-matches cleanly.
     *  - The plaintext is a fresh SecureRandom value that is DISCARDED (never
     *    stored, never logged), so no password — present or future — can match.
     *    A single per-JVM hash is sufficient: it is unguessable and never equal
     *    to a user-chosen password (which must satisfy PASSWORD_PATTERN anyway).
     */
    private static final String UNUSABLE_PASSWORD_HASH = generateUnusablePasswordHash();

    private static String generateUnusablePasswordHash() {
        byte[] rnd = new byte[32];
        new SecureRandom().nextBytes(rnd);
        // Base64 of 32 random bytes -> unguessable plaintext, immediately discarded.
        // Fully qualify: the framework package also defines a Base64 type.
        String throwaway = java.util.Base64.getEncoder().encodeToString(rnd);
        return new PasswordHasher().hashPassword(throwaway);
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JSONObject input = null;
        try {
            input = InputProcessor.getInput(req);
            String func = (String) input.get("_func");

            if (func == null || func.trim().isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Missing _func attribute.", req.getRequestURI());
                return;
            }

            // Get the ID of the Admin performing the action
            UUID loginUserId = InputProcessor.getAuthenticatedUserId(req);

            switch (func.toLowerCase()) {
                case "login":
                    handleLogin(input, res, req);
                    break;
                case "operator_session":
                    handleOperatorSession(input, res, req);
                    break;
                case "logout":
                    handleLogout(req, res);
                    break;
                case "generate_recovery_key":
                    handleGenerateRecoveryKey(input, loginUserId, res, req);
                    break;
                case "verify_recovery_key":
                    handleVerifyRecoveryKey(input, res, req);
                    break;
                case "reset_password_via_recovery":
                    handleResetViaRecovery(input, loginUserId, res, req);
                    break;
                case "list_users":
                    handleListUsers(input, res, req);
                    break;
                case "get_user":
                    handleGetUser(input, res, req);
                    break;
                case "create_user":
                    handleCreateUser(input, loginUserId, res, req);
                    break;
                case "update_user":
                    handleUpdateUser(input, loginUserId, res, req);
                    break;
                case "deactivate_user":
                    handleDeactivateUser(input, loginUserId, res, req);
                    break;
                default:
                    OutputProcessor.errorResponse(res, 400, "Bad Request", "Unsupported function: " + func, req.getRequestURI());
            }
        } catch (Exception e) {
            System.err.println("[ERROR] Operator.service: " + e);
            OutputProcessor.errorResponse(res, 500, "Internal Error", "An internal error occurred.", req.getRequestURI());
        }
    }

    private void handleLogin(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String clientIp = LoginRateLimiter.getClientIp(req);
        if (!LoginRateLimiter.isAllowed(clientIp)) {
            OutputProcessor.errorResponse(res, 429, "Too Many Requests", "Too many login attempts. Please try again later.", req.getRequestURI());
            return;
        }

        String identifier = (String) input.get("identifier");
        String password = (String) input.get("password");

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        boolean success = false;
        String principalEmail = null;
        UUID userUid = null;
        UUID fidUid = null;
        String role = null;
        String operatorName = null;
        JSONObject out = null;

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement(
                "SELECT o.id, o.name, " + DbEncryption.decryptCol("o.email_enc") + " AS email, o.password_hash, o.status, o.role, o.fiduciary_id, f.name AS fiduciary_name " +
                "FROM operators o LEFT JOIN fiduciaries f ON o.fiduciary_id = f.id " +
                "WHERE o.name = ? OR o.email_hmac = " + DbEncryption.HMAC);
            int loginIdx = DbEncryption.bindKey(pstmt, 1);    // param 1: decrypt key
            pstmt.setString(loginIdx++, identifier);           // param 2: name match
            DbEncryption.bindHmac(pstmt, loginIdx, identifier); // params 3,4: email_hmac match
            rs = pstmt.executeQuery();

            if (rs.next() && "ACTIVE".equals(rs.getString("status"))) {
                if (passwordHasher.verifyPassword(password, rs.getString("password_hash"))) {
                    principalEmail = rs.getString("email");
                    operatorName = rs.getString("name");
                    role = rs.getString("role");
                    final String token = JWTUtil.generateToken(principalEmail, identifier, role);
                    userUid = (UUID) rs.getObject("id");
                    fidUid = rs.getObject("fiduciary_id") != null ? (UUID) rs.getObject("fiduciary_id") : ADMIN_FID_UUID;

                    out = new JSONObject();
                    out.put("success", true);
                    out.put("token", token);
                    out.put("role", role);
                    out.put("username", operatorName);
                    out.put("fiduciary_id", fidUid.toString());
                    String fidName = rs.getString("fiduciary_name");
                    if (fidName != null) out.put("fiduciary_name", fidName);
                    success = true;
                }
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }

        String serviceType = null;
        if(role != null && role.equalsIgnoreCase("DPO")){
            serviceType = Constants.SERVICE_TYPE_DPO_CONSOLE;
        }else{
            serviceType = Constants.SERVICE_TYPE_ADMIN_CONSOLE;
        }

        if (success) {
            LoginRateLimiter.recordSuccess(clientIp);
            new Audit().logEventAsync(identifier, fidUid, serviceType, userUid, "LOGIN_SUCCESS", "Operator Access Granted");
            OutputProcessor.send(res, 200, out);
        }else{
            new Audit().logEventAsync(identifier, fidUid, serviceType, userUid, "LOGIN_FAILURE", "Invalid credentials or account inactive.");
            OutputProcessor.errorResponse(res, 401, "Unauthorized", "Invalid credentials or account inactive.", req.getRequestURI());
        }
    }

    /**
     * operator_session (vAIb-pigk) — mint a CMS operator JWT for the VERIFIED Wix
     * owner, WITHOUT a CMS password. The unified-identity console handoff: the
     * fabric has already verified the Wix-signed instance (owner) and resolved the
     * tenant's fiduciary_id from OpenBao; it proves itself to the CMS with the
     * OPERATOR_LOGIN_SECRET shared secret (EXACT mirror of principal_login).
     *
     * This is a PUBLIC/no-auth endpoint at the InterceptingFilter (reached via
     * /api/v1/public/operator, func=operator_session); the shared secret IS the
     * auth. It NEVER accepts a password and NEVER mints the platform-wide ADMIN
     * (null-fiduciary) session — it binds the JWT to an ACTIVE operator of the named
     * ACTIVE fiduciary, so the minted token is hard-scoped to that one tenant.
     * fiduciary_id is supplied by the fabric (server-derived from OpenBao), NOT free
     * client input the CMS trusts blindly.
     *
     * vAIb-q3g5 — AUTO-CREATE the owner operator when the tenant has none. Onboarded
     * tenants (unified identity; the Super-Admin-Setup operator-creation step was
     * removed) have ZERO operators, so there was nothing to bind to and the mint
     * 401'd. Now, INSIDE this already-secret-gated path, when the SELECT finds no
     * operator AND the fiduciary is ACTIVE, we create the owner's PASSWORDLESS ADMIN
     * operator (role=ADMIN, status=ACTIVE, password_hash=unusable sentinel,
     * recovery_key_hash=NULL) and bind to it. SAFE: the secret already proves the
     * trusted fabric (which only calls us AFTER verifying the Wix-signed OWNER
     * instance), and we still require the fiduciary to be ACTIVE. Idempotent:
     * concurrent first-mints converge on ONE row (unique-violation -> re-SELECT).
     * The auto-created operator can NEVER password-login (handleLogin's
     * verifyPassword no-matches the sentinel) — usable ONLY via this mint.
     *
     * On success returns {success, token, role, username, fiduciary_id,
     * fiduciary_name} — the SAME shape handleLogin returns, so the console pages
     * seed localStorage identically (authToken/role/username/fiduciary_id/
     * fiduciary_name). FAIL CLOSED at every rung: secret unset/mismatch -> 401;
     * bad/missing fiduciary_id -> 400; fiduciary inactive/unknown -> 401 (NO
     * auto-create — never invent an identity for a non-ACTIVE tenant).
     */
    private void handleOperatorSession(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String secret = (String) input.get("secret");
        String fiduciaryIdStr = (String) input.get("fiduciary_id");
        // Optional caller hint: which console role the owner is landing on. Used only
        // to PREFER a matching operator row; never to grant a role the tenant lacks.
        String rolePref = (String) input.get("role");
        // vAIb-cnv2 / vAIb-aqip — IDENTITY-BOUND DPO MODE. fabric proves (member
        // countersign + registered-DPO-email gate, console._verify_dpo_member) that the
        // caller IS the tenant's REGISTERED DPO, then forwards the whoami-VERIFIED member
        // email as operator_email + require_role='DPO'. We HONOUR these so the minted JWT
        // carries role=DPO bound to THAT email. This is load-bearing for the writer!=
        // approver gate: RoPA publish_entry (Ropa.handlePublishEntry) requires a DPO-role
        // approver, and a small tenant's owner-as-DPO has only an ADMIN operator, so
        // without this the DPO console would mint role=ADMIN and the DPO could never
        // approve. These arrive ONLY on the already-secret-gated path AFTER fabric proved
        // the DPO identity, so binding/creating a DPO operator for the verified email is
        // safe + fail-closed.
        String requireRole   = (String) input.get("require_role");
        String operatorEmail = (String) input.get("operator_email");
        boolean dpoBind = requireRole != null && requireRole.equalsIgnoreCase("DPO")
                && operatorEmail != null && EMAIL_PATTERN.matcher(operatorEmail.trim()).matches();

        // Gate 1: the fabric shared secret (constant-time, fail-closed if unset).
        if (OPERATOR_LOGIN_SECRET == null || secret == null
                || !MessageDigest.isEqual(OPERATOR_LOGIN_SECRET, secret.getBytes(StandardCharsets.UTF_8))) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid session secret.", req.getRequestURI());
            return;
        }

        if (fiduciaryIdStr == null || fiduciaryIdStr.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "fiduciary_id is required.", req.getRequestURI());
            return;
        }
        UUID fiduciaryId;
        try {
            fiduciaryId = UUID.fromString(fiduciaryIdStr);
        } catch (IllegalArgumentException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid fiduciary_id format.", req.getRequestURI());
            return;
        }

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        String email = null;
        String operatorName = null;
        String role = null;
        UUID userUid = null;
        UUID fidUid = null;
        String fiduciaryName = null;
        JSONObject out = null;
        boolean success = false;

        boolean autoCreated = false;
        try {
            conn = pool.getConnection();
            OwnerOperator bound;
            if (dpoBind) {
                // IDENTITY-BOUND DPO MINT (vAIb-aqip): bind to the ACTIVE DPO operator
                // whose email matches the verified registered DPO. If the tenant has no
                // such DPO operator (small tenant where the owner IS the DPO, or first
                // DPO login), AUTO-CREATE a passwordless DPO operator for the verified
                // email — distinct from the owner's ADMIN operator, so writer (ADMIN) and
                // approver (DPO) are SEPARATE identities even when the same person. SAFE:
                // we are inside the secret-valid path AND fabric already proved this email
                // is the tenant's registered DPO; fail-closed if the fiduciary is inactive.
                bound = selectActiveDpoOperator(conn, fiduciaryId, operatorEmail.trim());
                if (bound == null) {
                    bound = autoCreateDpoOperator(conn, fiduciaryId, operatorEmail.trim());
                    if (bound != null) autoCreated = true;
                }
            } else {
                // Bind to an EXISTING ACTIVE operator of THIS ACTIVE fiduciary. Prefer a
                // row matching the caller's role hint (e.g. DPO landing), else the most
                // recently created ACTIVE operator for the tenant. The JOIN to
                // fiduciaries enforces the fiduciary is ACTIVE (no session for a
                // suspended/deleted tenant). We never select the platform null-fiduciary
                // ADMIN here: fiduciary_id is a concrete tenant UUID.
                bound = selectActiveOperator(conn, fiduciaryId, rolePref);

                // vAIb-q3g5: onboarded tenants (unified identity, no Super-Admin-Setup
                // step) have ZERO operators, so the mint had nothing to bind to and
                // 401'd. When the SELECT finds none AND the fiduciary is ACTIVE, the
                // already-secret-gated fabric (which only calls us AFTER verifying the
                // Wix-signed OWNER instance) is allowed to AUTO-CREATE the owner's
                // passwordless ADMIN operator, then bind to it. SAFE because we are
                // already inside the secret-valid + concrete-tenant path; we still
                // require the fiduciary to be ACTIVE (fail-closed: never create for an
                // inactive/unknown tenant). Idempotent: a second mint finds the row.
                if (bound == null) {
                    bound = autoCreateOwnerOperator(conn, fiduciaryId, rolePref);
                    if (bound != null) autoCreated = true;
                }
            }

            if (bound != null) {
                email = bound.email;
                operatorName = bound.name;
                role = bound.role;
                userUid = bound.id;
                fiduciaryName = bound.fiduciaryName;
                fidUid = fiduciaryId;

                // Mint the operator JWT bound to the REAL operator email + role, so
                // downstream getVerifiedFiduciaryId/getVerifiedRole (which read the
                // signed JWT, falling back to the operators table by email/sub)
                // resolve to THIS tenant. Same JWTUtil.generateToken handleLogin
                // uses (subject=email, claims name+role) — isTokenValid accepts it.
                final String token = JWTUtil.generateToken(email, operatorName, role);

                out = new JSONObject();
                out.put("success", true);
                out.put("token", token);
                out.put("role", role);
                out.put("username", operatorName);
                out.put("fiduciary_id", fidUid.toString());
                if (fiduciaryName != null) out.put("fiduciary_name", fiduciaryName);
                success = true;
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }

        String serviceType = (role != null && role.equalsIgnoreCase("DPO"))
                ? Constants.SERVICE_TYPE_DPO_CONSOLE : Constants.SERVICE_TYPE_ADMIN_CONSOLE;

        if (success) {
            if (autoCreated) {
                // vAIb-9nb0: accurate audit string per role — DPO auto-create is a SEPARATE
                // passwordless DPO operator (writer!=approver), not the owner's ADMIN row.
                String autoCreateDetail = (role != null && role.equalsIgnoreCase("DPO"))
                        ? "Auto-created passwordless DPO operator (Wix unified identity)"
                        : "Auto-created passwordless owner ADMIN operator (Wix unified identity)";
                new Audit().logEventAsync(email, fidUid, serviceType, userUid, "OPERATOR_AUTO_CREATED", autoCreateDetail);
            }
            new Audit().logEventAsync(email, fidUid, serviceType, userUid, "OPERATOR_SESSION_MINTED", "Wix-owner console session (no password)");
            OutputProcessor.send(res, 200, out);
        } else {
            // Fiduciary inactive/unknown (or, defensively, still no operator) -> deny
            // (never invent an identity for a non-ACTIVE tenant). Generic message: do
            // not reveal whether the fiduciary or the operator was the missing piece.
            new Audit().logEventAsync(fiduciaryIdStr, fiduciaryId, Constants.SERVICE_TYPE_ADMIN_CONSOLE, null, "OPERATOR_SESSION_DENIED", "Inactive/unknown fiduciary — no console session minted or operator created.");
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "No console session available for this tenant.", req.getRequestURI());
        }
    }

    /**
     * Small holder for the operator row we bind the minted JWT to.
     */
    private static final class OwnerOperator {
        final UUID id;
        final String name;
        final String email;
        final String role;
        final String fiduciaryName;
        OwnerOperator(UUID id, String name, String email, String role, String fiduciaryName) {
            this.id = id; this.name = name; this.email = email; this.role = role; this.fiduciaryName = fiduciaryName;
        }
    }

    /**
     * SELECT the operator the operator_session mint binds to: an ACTIVE operator of
     * THIS ACTIVE fiduciary, preferring the caller's role hint. Returns null when
     * the tenant has no ACTIVE operator OR the fiduciary itself is not ACTIVE (the
     * JOIN enforces f.status = 'ACTIVE'). Pure read; caller owns the connection.
     */
    private OwnerOperator selectActiveOperator(Connection conn, UUID fiduciaryId, String rolePref) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT o.id, o.name, " + DbEncryption.decryptCol("o.email_enc") + " AS email, o.role, f.name AS fiduciary_name " +
                "FROM operators o JOIN fiduciaries f ON o.fiduciary_id = f.id " +
                "WHERE o.fiduciary_id = ? AND o.status = 'ACTIVE' AND f.status = 'ACTIVE' " +
                // SEC/UX FIX (owner-lands-on-DPO regression after the vAIb-9nb0 DPO auto-create):
                // when no role hint (plain owner app-url launch), an empty hint made the CASE never
                // match → it fell to created_at DESC → picked the NEWLY auto-created DPO row → the
                // OWNER landed on the (blank-for-owner) DPO dashboard. Default-prefer ADMIN so a
                // hintless owner launch binds to the ADMIN operator; an explicit ?role=dpo still
                // wins via the hint. Order: exact-hint-match, then ADMIN, then newest.
                "ORDER BY (CASE WHEN UPPER(o.role) = UPPER(?) THEN 0 WHEN UPPER(o.role) = 'ADMIN' THEN 1 ELSE 2 END), o.created_at DESC " +
                "LIMIT 1")) {
            int qi = DbEncryption.bindKey(ps, 1);          // param 1: decrypt key for email_enc
            ps.setObject(qi++, fiduciaryId);                 // fiduciary_id
            ps.setString(qi, rolePref != null ? rolePref : ""); // role hint
            try (ResultSet r = ps.executeQuery()) {
                if (r.next()) {
                    return new OwnerOperator(
                            (UUID) r.getObject("id"),
                            r.getString("name"),
                            r.getString("email"),
                            r.getString("role"),
                            r.getString("fiduciary_name"));
                }
            }
        }
        return null;
    }

    /**
     * vAIb-q3g5 — AUTO-CREATE the owner's passwordless ADMIN operator for a tenant
     * that has none, then return it bound for the mint. Called ONLY from the
     * secret-gated operator_session path AFTER the SELECT found no operator.
     *
     * Security invariants (all enforced here, fail-closed):
     *  - Runs in a SERIALIZABLE-not-required but COMMITTED transaction; we first
     *    re-confirm the fiduciary is ACTIVE *inside the tx with FOR UPDATE*. If it
     *    is not ACTIVE (inactive/unknown) we create NOTHING and return null -> the
     *    caller denies (same fail-closed gate as before).
     *  - role = ADMIN, status = ACTIVE, fiduciary_id = the verified tenant.
     *  - password_hash = UNUSABLE_PASSWORD_HASH (a "$2" BCrypt of a discarded
     *    random) and recovery_key_hash = NULL: the operator can NEVER password-login
     *    (handleLogin's verifyPassword no-matches it) — usable ONLY via this
     *    secret-gated mint.
     *  - name + email are made GLOBALLY UNIQUE by embedding the fiduciary UUID,
     *    because operators.name and operators.email_hmac both carry GLOBAL UNIQUE
     *    indexes (idx_operators_name_unique, idx_operators_email_hmac). The email is
     *    an identity LABEL, not a credential: prefer the fiduciary's own contact
     *    email when present, else a stable synthetic owner+<fid>@<primary_domain>.
     *  - IDEMPOTENT: a concurrent mint may insert first; we catch the unique
     *    violation (SQLState 23505) and re-SELECT, binding to the existing row so we
     *    never create a duplicate.
     *
     * Returns the bound operator, or null if the fiduciary is not ACTIVE.
     */
    private OwnerOperator autoCreateOwnerOperator(Connection conn, UUID fiduciaryId, String rolePref) throws SQLException {
        boolean priorAutoCommit = conn.getAutoCommit();
        conn.setAutoCommit(false);
        try {
            // 1) Re-confirm the fiduciary is ACTIVE inside the tx (FOR UPDATE serialises
            //    concurrent first-mints on the same tenant). Pull the identity fields we
            //    derive the owner label from. Inactive/unknown -> create nothing.
            String fidEmail = null, fidDomain = null;
            try (PreparedStatement fp = conn.prepareStatement(
                    "SELECT " + DbEncryption.decryptCol("email_enc") + " AS email, primary_domain, status " +
                    "FROM fiduciaries WHERE id = ? FOR UPDATE")) {
                int fi = DbEncryption.bindKey(fp, 1);   // decrypt key for email_enc
                fp.setObject(fi, fiduciaryId);
                try (ResultSet fr = fp.executeQuery()) {
                    if (!fr.next() || !"ACTIVE".equals(fr.getString("status"))) {
                        conn.rollback();
                        return null; // fail-closed: never create for an inactive/unknown tenant
                    }
                    fidEmail = fr.getString("email");
                    fidDomain = fr.getString("primary_domain");
                }
            }

            // 2) Derive a passwordless ADMIN owner identity. name + email are GLOBALLY
            //    unique (the unique indexes are global, not per-fiduciary), so embed the
            //    fiduciary UUID. email prefers the fiduciary's own contact email (a real
            //    identity label) but is NEVER a login credential.
            String ownerName = "Site Owner (Wix) " + fiduciaryId;
            String ownerEmail = deriveOwnerEmail(fidEmail, fidDomain, fiduciaryId);

            // 3) INSERT the passwordless ADMIN operator. Mirrors handleCreateUser's
            //    encrypted-email INSERT; password_hash = unusable sentinel,
            //    recovery_key_hash left NULL (column is nullable). We do not need the
            //    new id here — step 4 re-SELECTs and binds (covers the race too).
            try {
                String sql = "INSERT INTO operators (id, name, email_plaintext, email_enc, email_hmac, password_hash, recovery_key_hash, role, status, fiduciary_id, created_at, last_updated_at) " +
                        "VALUES (uuid_generate_v4(), ?, ?, " + DbEncryption.ENCRYPT + ", " + DbEncryption.HMAC + ", ?, NULL, 'ADMIN', 'ACTIVE', ?, NOW(), NOW())";
                try (PreparedStatement ins = conn.prepareStatement(sql)) {
                    int ci = 1;
                    ins.setString(ci++, ownerName);
                    ins.setString(ci++, ownerEmail);                 // email_plaintext
                    ci = DbEncryption.bindEncrypt(ins, ci, ownerEmail); // email_enc
                    ci = DbEncryption.bindHmac(ins, ci, ownerEmail);    // email_hmac
                    ins.setString(ci++, UNUSABLE_PASSWORD_HASH);     // password_hash (unusable)
                    ins.setObject(ci++, fiduciaryId);                 // fiduciary_id
                    ins.executeUpdate();
                }
                conn.commit();
            } catch (SQLException e) {
                // 23505 = unique_violation: a concurrent mint won the race. Roll back our
                // INSERT and fall through to re-SELECT the existing row (idempotent).
                if (!"23505".equals(e.getSQLState())) {
                    conn.rollback();
                    throw e;
                }
                conn.rollback();
            }

            // 4) Bind: re-SELECT (covers both our fresh INSERT and the concurrent-winner
            //    case). The SELECT re-enforces fiduciary ACTIVE + operator ACTIVE.
            OwnerOperator bound = selectActiveOperator(conn, fiduciaryId, rolePref);
            conn.commit();
            return bound;
        } catch (SQLException e) {
            try { conn.rollback(); } catch (SQLException ignore) {}
            throw e;
        } finally {
            conn.setAutoCommit(priorAutoCommit);
        }
    }

    /**
     * vAIb-aqip / vAIb-9nb0 — SELECT the ACTIVE role=DPO operator of THIS ACTIVE
     * fiduciary for the verified registered DPO. The DPO row is stored under a SYNTHETIC,
     * role-distinct email LABEL (deriveDpoOperatorEmail) so it can coexist with the
     * owner's ADMIN row under the GLOBAL UNIQUE operators.email_hmac index even when the
     * owner IS the DPO (same human, same real email). We match on the synthetic label's
     * email_hmac; we ALSO accept a row stored under the raw verified email (a DPO operator
     * provisioned via the admin console before this fix, where DPO email != owner email)
     * so existing tenants keep working. The JOIN enforces the fiduciary is ACTIVE. Pure
     * read; caller owns the connection.
     */
    private OwnerOperator selectActiveDpoOperator(Connection conn, UUID fiduciaryId, String email) throws SQLException {
        String dpoLabel = deriveDpoOperatorEmail(email, fiduciaryId);
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT o.id, o.name, " + DbEncryption.decryptCol("o.email_enc") + " AS email, o.role, f.name AS fiduciary_name " +
                "FROM operators o JOIN fiduciaries f ON o.fiduciary_id = f.id " +
                "WHERE o.fiduciary_id = ? AND o.status = 'ACTIVE' AND f.status = 'ACTIVE' " +
                "AND UPPER(o.role) = 'DPO' " +
                "AND (o.email_hmac = " + DbEncryption.HMAC + " OR o.email_hmac = " + DbEncryption.HMAC + ") " +
                "ORDER BY o.created_at DESC LIMIT 1")) {
            int qi = DbEncryption.bindKey(ps, 1);             // param 1: decrypt key for email_enc
            ps.setObject(qi++, fiduciaryId);                   // fiduciary_id
            qi = DbEncryption.bindHmac(ps, qi, dpoLabel);      // email_hmac match (synthetic DPO label)
            qi = DbEncryption.bindHmac(ps, qi, email);         // OR email_hmac match (legacy raw DPO email)
            try (ResultSet r = ps.executeQuery()) {
                if (r.next()) {
                    return new OwnerOperator(
                            (UUID) r.getObject("id"),
                            r.getString("name"),
                            r.getString("email"),
                            r.getString("role"),
                            r.getString("fiduciary_name"));
                }
            }
        }
        return null;
    }

    /**
     * vAIb-aqip — AUTO-CREATE a passwordless role=DPO operator bound to the VERIFIED
     * registered DPO email, then return it for the mint. Called ONLY from the secret-
     * gated operator_session DPO-bind path AFTER fabric proved (member countersign +
     * registered-DPO-email gate) that this email is the tenant's DPO, and ONLY when no
     * DPO operator exists yet.
     *
     * WHY a SEPARATE DPO operator (not reuse the owner ADMIN row): the writer!=approver
     * gate (Ropa.handlePublishEntry) requires a DPO-role approver. A small tenant whose
     * owner IS the DPO still gets TWO distinct operator identities — an ADMIN (drafts)
     * and a DPO (approves) — so the approval is an explicit DPO action, never an implicit
     * self-approve by the drafting ADMIN. Same fail-closed invariants as
     * autoCreateOwnerOperator: fiduciary re-confirmed ACTIVE FOR UPDATE; role=DPO,
     * status=ACTIVE; password_hash=UNUSABLE (mint-only, never a login); name globally
     * unique (carries the fiduciary UUID); idempotent on 23505 (concurrent winner ->
     * re-SELECT). Returns the bound DPO operator, or null if the fiduciary is not ACTIVE.
     */
    private OwnerOperator autoCreateDpoOperator(Connection conn, UUID fiduciaryId, String dpoEmail) throws SQLException {
        boolean priorAutoCommit = conn.getAutoCommit();
        conn.setAutoCommit(false);
        try {
            // 1) Re-confirm the fiduciary is ACTIVE inside the tx (FOR UPDATE serialises
            //    concurrent first-mints). Inactive/unknown -> create nothing (fail-closed).
            try (PreparedStatement fp = conn.prepareStatement(
                    "SELECT status FROM fiduciaries WHERE id = ? FOR UPDATE")) {
                fp.setObject(1, fiduciaryId);
                try (ResultSet fr = fp.executeQuery()) {
                    if (!fr.next() || !"ACTIVE".equals(fr.getString("status"))) {
                        conn.rollback();
                        return null;
                    }
                }
            }

            // 2) INSERT the passwordless DPO operator. BOTH name AND email are GLOBALLY
            //    unique (the unique indexes are global, not per-fiduciary), so we store a
            //    SYNTHETIC, role-distinct email LABEL (deriveDpoOperatorEmail, "dpo+<fid>@")
            //    rather than the raw verified DPO email — otherwise, when the owner IS the
            //    DPO, this collides with the owner's ADMIN row (same email_hmac) and the
            //    mint fails (vAIb-9nb0). The label is NEVER a login credential (password_hash
            //    is the unusable sentinel) and is never user-visible (fabric overrides the
            //    console display name from the verified email). The minted JWT subject is
            //    this label, so getVerifiedFiduciaryId resolves the DPO row to THIS tenant.
            String dpoName = "DPO (Wix) " + fiduciaryId;
            String dpoLabel = deriveDpoOperatorEmail(dpoEmail, fiduciaryId);
            try {
                String sql = "INSERT INTO operators (id, name, email_plaintext, email_enc, email_hmac, password_hash, recovery_key_hash, role, status, fiduciary_id, created_at, last_updated_at) " +
                        "VALUES (uuid_generate_v4(), ?, ?, " + DbEncryption.ENCRYPT + ", " + DbEncryption.HMAC + ", ?, NULL, 'DPO', 'ACTIVE', ?, NOW(), NOW())";
                try (PreparedStatement ins = conn.prepareStatement(sql)) {
                    int ci = 1;
                    ins.setString(ci++, dpoName);
                    ins.setString(ci++, dpoLabel);                   // email_plaintext (synthetic DPO label)
                    ci = DbEncryption.bindEncrypt(ins, ci, dpoLabel); // email_enc
                    ci = DbEncryption.bindHmac(ins, ci, dpoLabel);    // email_hmac
                    ins.setString(ci++, UNUSABLE_PASSWORD_HASH);      // password_hash (unusable)
                    ins.setObject(ci++, fiduciaryId);                  // fiduciary_id
                    ins.executeUpdate();
                }
                conn.commit();
            } catch (SQLException e) {
                // 23505 = unique_violation: a concurrent mint (or an existing DPO row with
                // this email) won the race. Roll back and fall through to re-SELECT.
                if (!"23505".equals(e.getSQLState())) {
                    conn.rollback();
                    throw e;
                }
                conn.rollback();
            }

            // 3) Bind: re-SELECT the DPO operator (covers our INSERT + the concurrent case).
            OwnerOperator bound = selectActiveDpoOperator(conn, fiduciaryId, dpoEmail);
            conn.commit();
            return bound;
        } catch (SQLException e) {
            try { conn.rollback(); } catch (SQLException ignore) {}
            throw e;
        } finally {
            conn.setAutoCommit(priorAutoCommit);
        }
    }

    /**
     * Derive the owner operator's email LABEL (never a credential). Prefer the
     * fiduciary's own contact email when it is a valid address; else a stable
     * synthetic owner+<fid>@<primary_domain> so it is globally unique and tied to
     * the tenant. Final fallback uses a sentinel host to stay well-formed.
     */
    private String deriveOwnerEmail(String fidEmail, String fidDomain, UUID fiduciaryId) {
        if (fidEmail != null && EMAIL_PATTERN.matcher(fidEmail.trim()).matches()) {
            return fidEmail.trim();
        }
        String host = (fidDomain != null && !fidDomain.trim().isEmpty())
                ? fidDomain.trim().toLowerCase().replaceAll("[^a-z0-9.-]", "")
                : "tenant.invalid";
        if (host.isEmpty()) host = "tenant.invalid";
        return "owner+" + fiduciaryId + "@" + host;
    }

    /**
     * vAIb-9nb0 — Derive the DPO operator's STORED email LABEL (never a credential).
     *
     * WHY a SYNTHETIC, role-distinct label (not the raw verified DPO email): when the
     * owner IS the DPO (a small tenant, the common case), the owner's auto-created ADMIN
     * operator ALREADY stores that exact email, and operators.email_hmac is a GLOBAL
     * UNIQUE index — so inserting a second (DPO) row with the same email collides
     * (SQLState 23505), the re-SELECT for role=DPO finds only the ADMIN row, the bind
     * returns null, and the mint fails -> the DPO console renders "temporarily
     * unavailable". Embedding the fiduciary UUID under a "dpo+" prefix yields a globally
     * unique, deterministic label distinct from deriveOwnerEmail's "owner+"/raw-contact
     * scheme, so the ADMIN (writer) and DPO (approver) stay SEPARATE operator identities
     * even for the same human. The minted JWT carries THIS label as its subject, so
     * downstream getVerifiedFiduciaryId (email_hmac lookup) resolves the DPO row to THIS
     * tenant; the console DISPLAY name is overridden by fabric from the verified email,
     * so the synthetic label is never user-visible. Host is taken from the verified DPO
     * email when valid (purely cosmetic), else a sentinel — uniqueness comes from the fid.
     */
    private String deriveDpoOperatorEmail(String verifiedDpoEmail, UUID fiduciaryId) {
        String host = "tenant.invalid";
        if (verifiedDpoEmail != null) {
            int at = verifiedDpoEmail.lastIndexOf('@');
            if (at > -1 && at < verifiedDpoEmail.length() - 1) {
                String h = verifiedDpoEmail.substring(at + 1).trim().toLowerCase()
                        .replaceAll("[^a-z0-9.-]", "");
                if (!h.isEmpty()) host = h;
            }
        }
        return "dpo+" + fiduciaryId + "@" + host;
    }

    private void handleLogout(HttpServletRequest req, HttpServletResponse res) {
        try {
            String authorization = req.getHeader("Authorization");
            if (authorization != null && authorization.startsWith("Bearer ")) {
                String token = authorization.substring(7);
                String jti = JWTUtil.getJtiFromToken(token);
                java.util.Date expiry = JWTUtil.getExpiryFromToken(token);
                if (jti != null && expiry != null) {
                    TokenBlocklist.revoke(jti, expiry.getTime());
                }
            }
            JSONObject out = new JSONObject();
            out.put("success", true);
            out.put("message", "Logged out successfully.");
            OutputProcessor.send(res, 200, out);
        } catch (Exception e) {
            System.err.println("[ERROR] Operator.handleLogout: " + e);
            OutputProcessor.errorResponse(res, 500, "Internal Error", "Logout failed.", req.getRequestURI());
        }
    }

    private void handleCreateUser(JSONObject input, UUID loginUserId, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String user = (String) input.get("username");
        String mail = (String) input.get("email");
        String pass = (String) input.get("password");
        String role = (String) input.get("role");
        String callerRole = InputProcessor.getVerifiedRole(req);
        if ("ADMIN".equalsIgnoreCase(role) && !"ADMIN".equalsIgnoreCase(callerRole)) {
            OutputProcessor.errorResponse(res, 403, "Forbidden", "Only ADMIN users may assign the ADMIN role.", req.getRequestURI());
            return;
        }

        // vAIb-2yn0 -- validate the assigned role against the KNOWN set (default-deny unknown
        // roles, so a typo / injected value can never create an operator with an unrecognised,
        // un-gated role). Recognised: ADMIN, DPO (tenant) + the 3 platform roles.
        String roleU = (role == null) ? "" : role.trim().toUpperCase();
        boolean isTenantRole = "ADMIN".equals(roleU) || "DPO".equals(roleU);
        boolean isPlatformRole = InputProcessor.isPlatformRole(roleU);
        if (!isTenantRole && !isPlatformRole) {
            OutputProcessor.errorResponse(res, 400, "Bad Request",
                    "Unrecognised role. Allowed: ADMIN, DPO, SUPER_ADMIN, ONBOARDING_MANAGER, SUPPORT_ASSISTANT.",
                    req.getRequestURI());
            return;
        }

        // vAIb-2yn0 -- only a PLATFORM SUPER_ADMIN may provision the platform roles
        // (SUPER_ADMIN / ONBOARDING_MANAGER / SUPPORT_ASSISTANT). A tenant operator (incl. the
        // Wix-owner ADMIN, concrete fiduciary) can NEVER mint a platform-scope user. The caller
        // role is server-verified (JWT/DB), never a client field. Default-deny: anything other
        // than a verified SUPER_ADMIN caller assigning a platform role is rejected.
        if (isPlatformRole && !InputProcessor.ROLE_SUPER_ADMIN.equalsIgnoreCase(callerRole)) {
            OutputProcessor.errorResponse(res, 403, "Forbidden",
                    "Only a platform SUPER_ADMIN may create platform-scope operators.", req.getRequestURI());
            return;
        }

        // vAIb-ae11: the new user is created in the SERVER-DERIVED tenant. A tenant operator
        // (incl. the Wix-owner ADMIN) can ONLY create users in their own fiduciary; only a
        // PLATFORM admin (null fiduciary) may target another tenant via the body fiduciary_id.
        UUID fid = InputProcessor.resolveTenantScope(req, res, false);
        if (fid == null) return;

        // vAIb-2yn0 -- a PLATFORM-scope role MUST be created with the NULL fiduciary (platform
        // scope). The discriminator is fiduciary NULL-vs-concrete: a SUPER_ADMIN bound to a
        // concrete tenant would be a contradiction (a tenant operator wearing a platform label),
        // so reject it. SUPER_ADMIN provisions platform users with NO body fiduciary_id (-> the
        // resolver yields PLATFORM_ADMIN_FID, persisted as NULL below). Conversely a TENANT role
        // (ADMIN/DPO) must NOT be created at platform scope (it needs a concrete fiduciary).
        boolean targetIsPlatformScope = InputProcessor.PLATFORM_ADMIN_FID.equals(fid);
        if (isPlatformRole && !targetIsPlatformScope) {
            OutputProcessor.errorResponse(res, 400, "Bad Request",
                    "A platform role must be created at platform scope (omit 'fiduciary_id').", req.getRequestURI());
            return;
        }
        if (isTenantRole && targetIsPlatformScope) {
            OutputProcessor.errorResponse(res, 400, "Bad Request",
                    "A tenant role (ADMIN/DPO) requires a concrete tenant -- specify 'fiduciary_id'.", req.getRequestURI());
            return;
        }

        if (mail == null || !EMAIL_PATTERN.matcher(mail).matches() || pass == null || !PASSWORD_PATTERN.matcher(pass).matches()) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Invalid email or weak password.", req.getRequestURI());
            return;
        }

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        boolean success = false;
        UUID newId = null;

        try {
            String sql = "INSERT INTO operators (id, name, email_plaintext, email_enc, email_hmac, password_hash, role, status, fiduciary_id, created_at, last_updated_at) " +
                    "VALUES (uuid_generate_v4(), ?, ?, " + DbEncryption.ENCRYPT + ", " + DbEncryption.HMAC + ", ?, ?, 'ACTIVE', ?, NOW(), NOW()) RETURNING id";

            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            int ci = 1;
            pstmt.setString(ci++, user);
            pstmt.setString(ci++, mail);                              // email_plaintext
            ci = DbEncryption.bindEncrypt(pstmt, ci, mail);          // email_enc
            ci = DbEncryption.bindHmac(pstmt, ci, mail);             // email_hmac
            pstmt.setString(ci++, passwordHasher.hashPassword(pass));
            pstmt.setString(ci++, role);
            pstmt.setObject(ci++, fid.equals(ADMIN_FID_UUID) ? null : fid);

            rs = pstmt.executeQuery();
            if (rs.next()) {
                newId = (UUID) rs.getObject(1);
                OutputProcessor.send(res, 201, new JSONObject() {{ put("success", true); }});
                success = true;
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }

        if (success) {
            new Audit().logEventAsync(mail, fid, Constants.SERVICE_TYPE_ADMIN_CONSOLE, loginUserId, "USER_CREATED", "Role assigned: " + role);
        }
    }

    private void handleUpdateUser(JSONObject input, UUID loginUserId, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        UUID uid = UUID.fromString((String) input.get("user_id"));
        String callerRole = InputProcessor.getVerifiedRole(req);
        // Fail-closed: a null/unverified role must not bypass the DPO self-only guard.
        if (callerRole == null) {
            OutputProcessor.errorResponse(res, 403, "Forbidden", "Verified role required.", req.getRequestURI());
            return;
        }
        if ("DPO".equalsIgnoreCase(callerRole) && !uid.equals(loginUserId)) {
            OutputProcessor.errorResponse(res, 403, "Forbidden", "DPO users may only update their own profile.", req.getRequestURI());
            return;
        }
        // vAIb-ae11: SERVER-DERIVED tenant scope. A tenant operator (incl. the Wix-owner, who is
        // role=ADMIN but bound to a concrete tenant) is hard-scoped to their own fiduciary; only a
        // PLATFORM admin (null fiduciary) may name the target tenant. The op never moves a user
        // across tenants (the UPDATE below is scoped to effectiveFid).
        UUID effectiveFid = InputProcessor.resolveTenantScope(req, res, true);
        if (effectiveFid == null) return;
        String user = (String) input.get("username");
        String pass = (String) input.get("password");
        // The target row stays within effectiveFid; this op never moves a user across tenants.
        UUID fid = effectiveFid;

        if (pass != null && !pass.isEmpty() && !PASSWORD_PATTERN.matcher(pass).matches()) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Weak password.", req.getRequestURI());
            return;
        }

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        boolean success = false;
        String targetEmail = null;

        try {
            conn = pool.getConnection();
            // Fetch target email for audit principal
            // Hardening: scope the lookup to effectiveFid unconditionally.
            try (PreparedStatement p = conn.prepareStatement(
                    "SELECT " + DbEncryption.decryptCol("email_enc") + " AS email FROM operators WHERE id = ? AND fiduciary_id = ?")) {
                int pi = DbEncryption.bindKey(p, 1);
                p.setObject(pi, uid);
                p.setObject(pi + 1, effectiveFid);
                try (ResultSet rs = p.executeQuery()) {
                    if (rs.next()) targetEmail = rs.getString("email");
                }
            }

            // Hardening: scope the UPDATE to effectiveFid unconditionally (cross-tenant = 0 rows).
            String sql = "UPDATE operators SET name = ?, fiduciary_id = ?, last_updated_at = NOW() " +
                    (pass != null && !pass.isEmpty() ? ", password_hash = ?" : "") +
                    " WHERE id = ? AND role != 'ADMIN' AND fiduciary_id = ?";

            pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, user);
            pstmt.setObject(2, fid.equals(ADMIN_FID_UUID) ? null : fid);
            int paramIdx = 3;
            if (pass != null && !pass.isEmpty()) {
                pstmt.setString(paramIdx++, passwordHasher.hashPassword(pass));
            }
            pstmt.setObject(paramIdx++, uid);
            pstmt.setObject(paramIdx, effectiveFid);

            if (pstmt.executeUpdate() > 0) {
                OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                success = true;
            } else {
                OutputProcessor.errorResponse(res, 403, "Forbidden", "Action restricted for system accounts.", req.getRequestURI());
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }

        if (success) {
            new Audit().logEventAsync(targetEmail, fid, Constants.SERVICE_TYPE_ADMIN_CONSOLE, loginUserId, "USER_UPDATED", "Profile modified");
        }
    }

    private void handleDeactivateUser(JSONObject input, UUID loginUserId, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        UUID uid = UUID.fromString((String) input.get("user_id"));
        String callerRole = InputProcessor.getVerifiedRole(req);
        // Fail-closed: a null/unverified role must not bypass the DPO self-only guard.
        if (callerRole == null) {
            OutputProcessor.errorResponse(res, 403, "Forbidden", "Verified role required.", req.getRequestURI());
            return;
        }
        if ("DPO".equalsIgnoreCase(callerRole) && !uid.equals(loginUserId)) {
            OutputProcessor.errorResponse(res, 403, "Forbidden", "DPO users may only deactivate their own profile.", req.getRequestURI());
            return;
        }
        // vAIb-ae11: SERVER-DERIVED tenant scope (hard-scoped for tenant operators incl. the
        // Wix-owner ADMIN; platform admin names the target). The UPDATE below is scoped to it.
        UUID effectiveFid = InputProcessor.resolveTenantScope(req, res, true);
        if (effectiveFid == null) return;
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        boolean success = false;
        String targetEmail = null;

        try {
            conn = pool.getConnection();
            // Fetch email for audit
            // Hardening: scope the lookup to effectiveFid unconditionally.
            try (PreparedStatement p = conn.prepareStatement(
                    "SELECT " + DbEncryption.decryptCol("email_enc") + " AS email FROM operators WHERE id = ? AND fiduciary_id = ?")) {
                int pi = DbEncryption.bindKey(p, 1);
                p.setObject(pi, uid);
                p.setObject(pi + 1, effectiveFid);
                try (ResultSet rs = p.executeQuery()) {
                    if (rs.next()) targetEmail = rs.getString("email");
                }
            }

            // Hardening: scope the UPDATE to effectiveFid unconditionally (cross-tenant = no-op).
            pstmt = conn.prepareStatement("UPDATE operators SET status = 'INACTIVE', last_updated_at = NOW() WHERE id = ? AND role != 'ADMIN' AND fiduciary_id = ?");
            pstmt.setObject(1, uid);
            pstmt.setObject(2, effectiveFid);
            pstmt.executeUpdate();
            success = true;
        } catch(Exception e) {
            System.err.println("[ERROR] Operator.deactivateUser: " + e);
        } finally {
            pool.cleanup(null, pstmt, conn);
        }

        if (success) {
            new Audit().logEventAsync(targetEmail, ADMIN_FID_UUID, Constants.SERVICE_TYPE_ADMIN_CONSOLE, loginUserId, "USER_DEACTIVATED", "Account disabled");
        }
    }

    private void handleResetViaRecovery(JSONObject input, UUID loginUserId, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String email = (String) input.get("email");
        String passphrase = (String) input.get("passphrase");
        String newPassword = (String) input.get("new_password");

        // vAIb-83bu (security): THROTTLE the recovery guess. This is an UNAUTHENTICATED path
        // (the recovery phrase IS the credential) whose email lookup is CROSS-TENANT unscoped,
        // so an un-throttled guess is a realistic account-takeover of ANY operator (incl a
        // platform admin). Reuse the SAME LoginRateLimiter as handleLogin (5 attempts / 15 min),
        // keyed on client-IP + email so neither a single IP nor a single targeted email can be
        // brute-forced. 429 on exceed. No recordSuccess() — every attempt counts (defence: a
        // valid reset should be rare; we never want to reset the counter on a lucky hit).
        String rlKey = LoginRateLimiter.getClientIp(req) + "|recovery|" + (email == null ? "" : email);
        if (!LoginRateLimiter.isAllowed(rlKey)) {
            OutputProcessor.errorResponse(res, 429, "Too Many Requests", "Too many recovery attempts. Please try again later.", req.getRequestURI());
            return;
        }

        if (!PASSWORD_PATTERN.matcher(newPassword).matches()) {
            OutputProcessor.errorResponse(res, 400, "Bad Request", "Password complexity failed.", req.getRequestURI());
            return;
        }

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        boolean success = false;
        UUID userId = null;
        UUID fidId = null;

        try {
            conn = pool.getConnection();
            conn.setAutoCommit(false);

            pstmt = conn.prepareStatement("SELECT id, recovery_key_hash, fiduciary_id FROM operators WHERE email_hmac = " + DbEncryption.HMAC + " AND status = 'ACTIVE' FOR UPDATE");
            DbEncryption.bindHmac(pstmt, 1, email);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                String storedHash = rs.getString("recovery_key_hash");
                userId = (UUID) rs.getObject("id");
                fidId = rs.getObject("fiduciary_id") != null ? (UUID) rs.getObject("fiduciary_id") : ADMIN_FID_UUID;

                if (storedHash != null && passwordHasher.verifyPassword(passphrase, storedHash)) {
                    try (PreparedStatement uPstmt = conn.prepareStatement("UPDATE operators SET password_hash = ?, recovery_key_hash = NULL, last_updated_at = NOW() WHERE id = ?")) {
                        uPstmt.setString(1, passwordHasher.hashPassword(newPassword));
                        uPstmt.setObject(2, userId);
                        uPstmt.executeUpdate();
                    }
                    conn.commit();
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    success = true;
                }
            }
            if (!success) {
                conn.rollback();
                OutputProcessor.errorResponse(res, 401, "Unauthorized", "Reset failed.", req.getRequestURI());
            }
        } catch (Exception e) {
            if (conn != null) conn.rollback();
            throw e;
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }

        if (success) {
            new Audit().logEventAsync(email, fidId, Constants.SERVICE_TYPE_ADMIN_CONSOLE, loginUserId != null ? loginUserId : userId, "PASSWORD_RECOVERY_SUCCESS", "Self-service recovery");
        }
    }

    private void handleGenerateRecoveryKey(JSONObject input, UUID loginUserId, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        UUID uid = UUID.fromString((String) input.get("user_id"));
        // vAIb-ae11: SERVER-DERIVED tenant scope (hard-scoped for tenant operators incl. the
        // Wix-owner ADMIN; platform admin names the target). The lookup/UPDATE are scoped to it.
        UUID effectiveFid = InputProcessor.resolveTenantScope(req, res, true);
        if (effectiveFid == null) return;
        String plainKey = PassphraseGenerator.generate();

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        boolean success = false;
        String targetEmail = null;

        try {
            conn = pool.getConnection();
            // Hardening: scope the lookup to effectiveFid unconditionally.
            try (PreparedStatement p = conn.prepareStatement(
                    "SELECT " + DbEncryption.decryptCol("email_enc") + " AS email FROM operators WHERE id = ? AND fiduciary_id = ?")) {
                int pi = DbEncryption.bindKey(p, 1);
                p.setObject(pi, uid);
                p.setObject(pi + 1, effectiveFid);
                try (ResultSet rs = p.executeQuery()) {
                    if (rs.next()) targetEmail = rs.getString("email");
                }
            }

            // Hardening: scope the UPDATE to effectiveFid unconditionally (cross-tenant = no-op).
            pstmt = conn.prepareStatement("UPDATE operators SET recovery_key_hash = ?, last_updated_at = NOW() WHERE id = ? AND fiduciary_id = ?");
            pstmt.setString(1, passwordHasher.hashPassword(plainKey));
            pstmt.setObject(2, uid);
            pstmt.setObject(3, effectiveFid);

            if (pstmt.executeUpdate() > 0) {
                OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); put("passphrase", plainKey); }});
                success = true;
            }
        } finally {
            pool.cleanup(null, pstmt, conn);
        }

        if (success) {
            new Audit().logEventAsync(targetEmail, ADMIN_FID_UUID, Constants.SERVICE_TYPE_ADMIN_CONSOLE, loginUserId, "RECOVERY_KEY_ROTATED", "New Master Key generated");
        }
    }

    private void handleVerifyRecoveryKey(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        String email = (String) input.get("email");
        String passphrase = (String) input.get("passphrase");

        // vAIb-83bu (security): THROTTLE the verify oracle. verify_recovery_key is a FREE
        // confirmation oracle for a guessed phrase (200 = "this phrase is correct"), so it must
        // be rate-limited exactly like the reset path. SAME LoginRateLimiter (5 / 15 min), same
        // IP+email key (shared bucket with the reset path — a mix of verify+reset guesses is
        // bounded together). 429 on exceed.
        String rlKey = LoginRateLimiter.getClientIp(req) + "|recovery|" + (email == null ? "" : email);
        if (!LoginRateLimiter.isAllowed(rlKey)) {
            OutputProcessor.errorResponse(res, 429, "Too Many Requests", "Too many recovery attempts. Please try again later.", req.getRequestURI());
            return;
        }

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT recovery_key_hash FROM operators WHERE email_hmac = " + DbEncryption.HMAC + " AND status = 'ACTIVE'");
            DbEncryption.bindHmac(pstmt, 1, email);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                String storedHash = rs.getString("recovery_key_hash");
                if (storedHash != null && passwordHasher.verifyPassword(passphrase, storedHash)) {
                    OutputProcessor.send(res, 200, new JSONObject() {{ put("success", true); }});
                    return;
                }
            }
            OutputProcessor.errorResponse(res, 401, "Unauthorized", "Invalid verification key.", req.getRequestURI());
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private void handleListUsers(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        // vAIb-ae11: scope to the SERVER-DERIVED tenant. Previously this returned EVERY tenant's
        // operators (names + emails) to any caller. A tenant operator now sees ONLY their own
        // tenant's CMS users; a PLATFORM admin (null fiduciary) sees all.
        UUID scope = InputProcessor.resolveTenantScope(req, res, false);
        if (scope == null) return;
        boolean platform = InputProcessor.PLATFORM_ADMIN_FID.equals(scope);

        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        JSONArray arr = new JSONArray();

        try {
            String sql = "SELECT u.id, u.name, " + DbEncryption.decryptCol("u.email_enc") + " AS email, u.status, u.role, u.fiduciary_id, f.name as fiduciary_name " +
                    "FROM operators u LEFT JOIN fiduciaries f ON u.fiduciary_id = f.id " +
                    (platform ? "" : "WHERE u.fiduciary_id = ? ") +
                    "ORDER BY u.created_at DESC";

            conn = pool.getConnection();
            pstmt = conn.prepareStatement(sql);
            int li = DbEncryption.bindKey(pstmt, 1);
            if (!platform) pstmt.setObject(li, scope);
            rs = pstmt.executeQuery();

            while (rs.next()) {
                JSONObject u = new JSONObject();
                u.put("user_id", rs.getString("id"));
                u.put("username", rs.getString("name"));
                u.put("email", rs.getString("email"));
                u.put("status", rs.getString("status"));
                u.put("role", rs.getString("role"));
                u.put("fiduciary_id", rs.getString("fiduciary_id"));
                u.put("fiduciary_name", rs.getString("fiduciary_name"));
                arr.add(u);
            }
            OutputProcessor.send(res, 200, arr);
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    private void handleGetUser(JSONObject input, HttpServletResponse res, HttpServletRequest req) throws SQLException {
        UUID uid = UUID.fromString((String) input.get("user_id"));
        // vAIb-ae11: scope the by-id read to the SERVER-DERIVED tenant. A tenant operator is
        // hard-scoped to their own fiduciary; only a PLATFORM admin may name the target tenant.
        UUID effectiveFid = InputProcessor.resolveTenantScope(req, res, true);
        if (effectiveFid == null) return;
        PoolDB pool = new PoolDB();
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;

        try {
            conn = pool.getConnection();
            pstmt = conn.prepareStatement("SELECT id, name, " + DbEncryption.decryptCol("email_enc") + " AS email, fiduciary_id, role FROM operators WHERE id = ? AND fiduciary_id = ?");
            int gi = DbEncryption.bindKey(pstmt, 1);
            pstmt.setObject(gi, uid);
            pstmt.setObject(gi + 1, effectiveFid);
            rs = pstmt.executeQuery();

            if (rs.next()) {
                JSONObject u = new JSONObject();
                u.put("user_id", rs.getString("id"));
                u.put("username", rs.getString("name"));
                u.put("email", rs.getString("email"));
                u.put("fiduciary_id", rs.getString("fiduciary_id"));
                u.put("role_name", rs.getString("role"));
                OutputProcessor.send(res, 200, u);
            }
        } finally {
            pool.cleanup(rs, pstmt, conn);
        }
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return "POST".equalsIgnoreCase(method);
    }
}