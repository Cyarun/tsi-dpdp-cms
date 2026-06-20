# vAIb-q3g5 — operator auto-create proofs

These are standalone, dependency-light proofs for the `operator_session`
auto-create-owner change in `src/.../service/v1/Operator.java`. They live OUTSIDE
`src/` so the WAR build (`<sourceDirectory>src</sourceDirectory>`) never ships them.

There is no JUnit/Surefire wired into this project; these run as plain `main`
classes so they can be executed without adding test-harness dependencies.

## 1. SentinelProof — password-login REJECTS the auto-created operator

Proves the `UNUSABLE_PASSWORD_HASH` sentinel (a `$2` BCrypt of a discarded random)
is rejected by the exact `PasswordHasher.verifyPassword` that `handleLogin` uses —
for every candidate password, with no match and no thrown exception.

```bash
JB=path/to/jbcrypt-0.4.jar
javac --release 15 -cp "$JB" -d /tmp/out \
    src/org/tsicoop/dpdpcms/framework/PasswordHasher.java \
    test/org/tsicoop/dpdpcms/SentinelProof.java
java -cp "/tmp/out:$JB" org.tsicoop.dpdpcms.SentinelProof
```

## 2. AutoCreateIT + RaceIT — integration against a real Postgres

Drive the REAL `Operator.autoCreateOwnerOperator` / `selectActiveOperator`
(private, via reflection) against a throwaway Postgres:

- `AutoCreateIT`: ACTIVE-tenant-no-operator -> creates ONE passwordless ADMIN +
  binds; idempotent second call (no dup); INACTIVE/unknown fiduciary -> no
  create (fail-closed); sentinel password_hash + NULL recovery_key_hash; email
  derivation (fiduciary contact, else synthetic `owner+<fid>@<domain>`).
- `RaceIT`: N concurrent first-mints converge on EXACTLY ONE row (23505
  unique-violation -> re-SELECT), all callers bind, no errors.

```bash
# 1) Postgres with the relevant schema (see test fixture below)
docker run -d --name pg -e POSTGRES_PASSWORD=test -e POSTGRES_DB=cmstest \
    -p 55433:5432 postgres:15-alpine
# extensions + fiduciaries/operators tables + GLOBAL unique indexes on
# operators(name) and operators(email_hmac); seed ACTIVE/INACTIVE fiduciaries.

# 2) Compile against the project deps (DB_ENCRYPTION_KEY must match the seed key)
CP="all-project-deps.jar:..."
javac --release 15 -cp "$CP" -d /tmp/out $(find src -name '*.java' ! -name KmsService.java)
javac --release 15 -cp "$CP:/tmp/out" -d /tmp/out \
    test/org/tsicoop/dpdpcms/AutoCreateIT.java test/org/tsicoop/dpdpcms/RaceIT.java

# 3) Run
DB_ENCRYPTION_KEY=testkey123 OPERATOR_LOGIN_SECRET=dummy \
    java -cp "/tmp/out:$CP" org.tsicoop.dpdpcms.AutoCreateIT
DB_ENCRYPTION_KEY=testkey123 OPERATOR_LOGIN_SECRET=dummy \
    java -cp "/tmp/out:$CP" org.tsicoop.dpdpcms.RaceIT
```

All three exit 0 on success.
