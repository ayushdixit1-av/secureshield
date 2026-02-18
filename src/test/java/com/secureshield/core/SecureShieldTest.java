package com.secureshield.core;

import com.secureshield.exception.AuthenticationException;
import com.secureshield.exception.InvalidTokenException;
import com.secureshield.model.SecurityContext;
import com.secureshield.model.TokenClaims;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class SecureShieldTest {

    @Test
    void accessAndRefreshTokenFlowShouldWork() {
        String access = SecureShield.createAccessToken("ayush", Set.of("ADMIN"));
        String refresh = SecureShield.createRefreshToken("ayush", Set.of("ADMIN"));

        assertTrue(SecureShield.verifyToken(access));
        assertTrue(SecureShield.verifyAccessToken(access));
        assertTrue(SecureShield.verifyRefreshToken(refresh));

        TokenClaims claims = SecureShield.extractClaims(access);
        assertEquals("ayush", claims.subject());
        assertEquals("access", claims.tokenType());

        String refreshedAccess = SecureShield.refreshAccessToken(refresh);
        assertTrue(SecureShield.verifyToken(refreshedAccess));

        SecureShield.revokeToken(refreshedAccess);
        assertFalse(SecureShield.verifyToken(refreshedAccess));
    }

    @Test
    void refreshTokenReuseShouldBeRejected() {
        String refresh = SecureShield.createRefreshToken("ayush", Set.of("USER"));

        SecureShield.refreshAccessToken(refresh);

        assertThrows(InvalidTokenException.class, () -> SecureShield.refreshAccessToken(refresh));
    }

    @Test
    void passwordHashingAndVerificationShouldWork() {
        String hash = SecureShield.hashPassword("Strong@Pass1");
        assertNotNull(hash);
        assertTrue(SecureShield.verifyPassword("Strong@Pass1", hash));
        assertFalse(SecureShield.verifyPassword("Wrong@Pass1", hash));
    }

    @Test
    void weakPasswordShouldBeRejected() {
        assertThrows(AuthenticationException.class, () -> SecureShield.hashPassword("weakpass"));
    }

    @Test
    void rbacShouldWorkForAdminAndUser() {
        assertTrue(SecureShield.hasPermission("ADMIN", "DELETE_USER"));
        assertFalse(SecureShield.hasPermission("USER", "DELETE_USER"));

        SecurityContext context = SecureShield.buildSecurityContext("ayush", Set.of("USER"));
        assertTrue(context.hasRole("USER"));
        assertTrue(context.hasPermission("READ_PROFILE"));
    }

    @Test
    void encryptionDecryptionShouldWork() {
        SecretKey key = SecureShield.generateSecretKey();
        String encrypted = SecureShield.encrypt("hello-world", key);
        String decrypted = SecureShield.decrypt(encrypted, key);

        assertEquals("hello-world", decrypted);
    }

    @Test
    void sessionShouldBeCreatedValidatedAndRevoked() {
        String session = SecureShield.createSession(1000);
        assertTrue(SecureShield.validateSession(session));

        SecureShield.revokeSession(session);
        assertFalse(SecureShield.validateSession(session));
    }

    @Test
    void authenticationShouldThrowOnWrongPassword() {
        String hash = SecureShield.hashPassword("Strong@Pass1");
        assertThrows(AuthenticationException.class, () ->
                SecureShield.authenticateOrThrow("ayush", "wrong", hash));
    }

    @Test
    void accountShouldTemporarilyLockAfterRepeatedFailures() {
        String hash = SecureShield.hashPassword("Strong@Pass1");

        for (int i = 0; i < 5; i++) {
            assertThrows(AuthenticationException.class,
                    () -> SecureShield.authenticateOrThrow("locked-user", "wrong", hash));
        }

        assertThrows(AuthenticationException.class,
                () -> SecureShield.authenticateOrThrow("locked-user", "Strong@Pass1", hash));
    }

    @Test
    void basicDeveloperFriendlyApiShouldWork() {
        String token = SecureShield.createToken("user");
        assertTrue(SecureShield.verifyToken(token));

        String hash = SecureShield.hashPassword("Strong@Pass1");
        assertTrue(SecureShield.verifyPassword("Strong@Pass1", hash));
    }

    @Test
    void legacyTokenServiceShouldStillWork() {
        com.secureshield.jwt.TokenService legacy = new com.secureshield.jwt.TokenService();
        String token = legacy.createToken("legacy-user");

        assertTrue(legacy.verifyToken(token));
        assertEquals("legacy-user", legacy.extractUsername(token));
    }

}
