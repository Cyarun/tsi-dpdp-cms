package org.tsicoop.dpdpcms.framework;

import org.mindrot.jbcrypt.BCrypt;

public class PasswordHasher {

    private static final int BCRYPT_LOG_ROUNDS = 12; // A common, secure value

    /**
     * Hashes a plaintext password using BCrypt.
     * @param plaintextPassword The password in plain text.
     * @return The hashed password.
     */
    public String hashPassword(String plaintextPassword) {
        // Generate a salt and hash the password
        String salt = BCrypt.gensalt(BCRYPT_LOG_ROUNDS);
        //String salt = System.getenv("TSI_AADHAR_VAULT_SALT");
        return BCrypt.hashpw(plaintextPassword, salt);
    }

    /**
     * Verifies a plaintext password against a stored hashed password.
     * @param plaintextPassword The password in plain text.
     * @param hashedPassword The hashed password stored in the database.
     * @return true if the password matches, false otherwise.
     */
    public boolean checkPassword(String plaintextPassword, String hashedPassword) {
        // Fail-safe: a null/malformed stored hash must mean "auth fails", never a
        // thrown exception that aborts the whole DB transaction. BCrypt.checkpw
        // throws IllegalArgumentException "Invalid salt version" on a non-BCrypt
        // value (e.g. a legacy/un-migrated hash), so guard + catch it.
        if (plaintextPassword == null || hashedPassword == null
                || !hashedPassword.startsWith("$2")) {
            System.err.println("[WARN] checkPassword: stored hash not BCrypt ("
                    + (hashedPassword == null ? "null" : "len=" + hashedPassword.length()
                       + " prefix=" + hashedPassword.substring(0, Math.min(4, hashedPassword.length())))
                    + ") — treating as no-match");
            return false;
        }
        try {
            return BCrypt.checkpw(plaintextPassword, hashedPassword);
        } catch (IllegalArgumentException e) {
            System.err.println("[WARN] checkPassword: BCrypt rejected stored hash: " + e.getMessage());
            return false;
        }
    }

    /**
     * Verifies a plain-text password against a BCrypt hashed password.
     *
     * @param plainTextPassword The password provided by the user (in plain text).
     * @param hashedPassword The stored BCrypt hashed password from the database.
     * @return true if the plain-text password matches the hash, false otherwise.
     */
    public boolean verifyPassword(String plainTextPassword, String hashedPassword) {
        if (plainTextPassword == null || hashedPassword == null) {
            // Handle null inputs gracefully, perhaps throw IllegalArgumentException or return false
            return false;
        }
        // BCrypt.checkpw(plain_password, hashed_password)
        // This method handles extracting the salt from the hashed password and comparing.
        return BCrypt.checkpw(plainTextPassword, hashedPassword);
    }
}