package com.secureshield.core;

import com.secureshield.attack.BruteForceProtector;
import com.secureshield.audit.AuditLogger;
import com.secureshield.config.SecureShieldConfig;
import com.secureshield.crypto.DecryptionService;
import com.secureshield.crypto.EncryptionService;
import com.secureshield.exception.AuthenticationException;
import com.secureshield.jwt.JWTService;
import com.secureshield.model.SecurityContext;
import com.secureshield.model.TokenClaims;
import com.secureshield.password.PasswordService;
import com.secureshield.password.PasswordValidator;
import com.secureshield.rate.RateLimiter;
import com.secureshield.session.SessionService;
import com.secureshield.util.CryptoUtils;

import javax.crypto.SecretKey;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Developer-friendly facade API.
 */
public final class SecureShield {
    private static final SecureShieldConfig CONFIG = new SecureShieldConfig();
    private static final JWTService JWT_SERVICE = new JWTService(CONFIG);
    private static final PasswordValidator PASSWORD_VALIDATOR = new PasswordValidator(CONFIG);
    private static final PasswordService PASSWORD_SERVICE = new PasswordService(PASSWORD_VALIDATOR);
    private static final EncryptionService ENCRYPTION_SERVICE = new EncryptionService();
    private static final DecryptionService DECRYPTION_SERVICE = new DecryptionService();
    private static final SessionService SESSION_SERVICE = new SessionService();
    private static final RateLimiter RATE_LIMITER = new RateLimiter(CONFIG.maxRequestsPerMinute());
    private static final BruteForceProtector BRUTE_FORCE_PROTECTOR =
            new BruteForceProtector(CONFIG.maxLoginAttempts(), CONFIG.lockDurationMs());
    private static final AuditLogger AUDIT_LOGGER = new AuditLogger();

    private static final Map<String, Set<String>> ROLE_PERMISSIONS = new ConcurrentHashMap<>();

    static {
        defineRole("ADMIN", Set.of("*"));
        defineRole("USER", Set.of("READ_PROFILE", "UPDATE_PROFILE"));
    }

    private SecureShield() {
    }

    public static String createToken(String username) {
        String token = JWT_SERVICE.createAccessToken(username, Set.of("USER"));
        AUDIT_LOGGER.tokenCreated(username);
        return token;
    }

    public static String createAccessToken(String username, Set<String> roles) {
        String token = JWT_SERVICE.createAccessToken(username, roles);
        AUDIT_LOGGER.tokenCreated(username);
        return token;
    }

    public static String createRefreshToken(String username, Set<String> roles) {
        return JWT_SERVICE.createRefreshToken(username, roles);
    }

    public static boolean verifyToken(String token) {
        boolean valid = JWT_SERVICE.verifyToken(token);
        if (!valid) {
            AUDIT_LOGGER.tokenVerificationFailure("invalid_or_expired");
        }
        return valid;
    }

    public static boolean verifyAccessToken(String token) {
        return JWT_SERVICE.verifyAccessToken(token);
    }

    public static boolean verifyRefreshToken(String token) {
        return JWT_SERVICE.verifyRefreshToken(token);
    }

    public static TokenClaims extractClaims(String token) {
        return JWT_SERVICE.extractClaims(token);
    }

    public static String refreshAccessToken(String refreshToken) {
        return JWT_SERVICE.refreshAccessToken(refreshToken);
    }

    public static void revokeToken(String token) {
        JWT_SERVICE.revokeToken(token);
    }

    public static String hashPassword(String password) {
        return PASSWORD_SERVICE.hashPassword(password);
    }

    public static boolean verifyPassword(String password, String hash) {
        return PASSWORD_SERVICE.verifyPassword(password, hash);
    }

    public static boolean checkPassword(String password, String hash) {
        return verifyPassword(password, hash);
    }

    public static void defineRole(String role, Set<String> permissions) {
        ROLE_PERMISSIONS.put(role, permissions == null ? Collections.emptySet() : permissions);
    }

    public static boolean hasPermission(String role, String permission) {
        Set<String> permissions = ROLE_PERMISSIONS.get(role);
        return permissions != null && (permissions.contains("*") || permissions.contains(permission));
    }

    public static SecurityContext buildSecurityContext(String username, Set<String> roles) {
        Set<String> permissions = ConcurrentHashMap.newKeySet();
        for (String role : roles) {
            Set<String> rolePermissions = ROLE_PERMISSIONS.get(role);
            if (rolePermissions != null) {
                permissions.addAll(rolePermissions);
            }
        }
        return new SecurityContext(username, roles, permissions);
    }

    public static SecretKey generateSecretKey() {
        return CryptoUtils.generateAesKey(256);
    }

    public static String encrypt(String plaintext, SecretKey key) {
        return ENCRYPTION_SERVICE.encrypt(plaintext, key);
    }

    public static String decrypt(String ciphertext, SecretKey key) {
        return DECRYPTION_SERVICE.decrypt(ciphertext, key);
    }

    public static String createSession(long ttlMs) {
        return SESSION_SERVICE.createSession(ttlMs);
    }

    public static boolean validateSession(String sessionId) {
        return SESSION_SERVICE.validateSession(sessionId);
    }

    public static void revokeSession(String sessionId) {
        SESSION_SERVICE.revokeSession(sessionId);
    }

    public static boolean allowRequestForUser(String username) {
        return RATE_LIMITER.allow("user:" + username);
    }

    public static boolean allowRequestForIp(String ipAddress) {
        return RATE_LIMITER.allow("ip:" + ipAddress);
    }

    public static void authenticateOrThrow(String username, String rawPassword, String storedHash) {
        if (BRUTE_FORCE_PROTECTOR.isLocked(username)) {
            throw new AuthenticationException("Account temporarily locked due to repeated failures");
        }

        if (!allowRequestForUser(username)) {
            BRUTE_FORCE_PROTECTOR.registerFailure(username);
            throw new AuthenticationException("Too many login attempts. Temporarily locked.");
        }

        if (!verifyPassword(rawPassword, storedHash)) {
            BRUTE_FORCE_PROTECTOR.registerFailure(username);
            AUDIT_LOGGER.loginFailure(username);
            throw new AuthenticationException("Invalid credentials");
        }

        BRUTE_FORCE_PROTECTOR.registerSuccess(username);
        AUDIT_LOGGER.loginSuccess(username);
    }
}
