package com.secureshield.util;

import java.nio.charset.StandardCharsets;

/**
 * Centralized security configuration.
 */
public final class SecurityConfig {

    private static final String DEFAULT_SECRET = "secureshield-default-secret-key-change-in-production-2026";
    private static final long DEFAULT_EXPIRATION_MILLIS = 60 * 60 * 1000; // 1 hour

    private SecurityConfig() {
    }

    public static byte[] secretKeyBytes() {
        String configured = System.getProperty("secureshield.secret");

        if (configured == null || configured.isBlank()) {
            configured = System.getenv("SECURESHIELD_SECRET");
        }

        if (configured == null || configured.isBlank()) {
            configured = DEFAULT_SECRET;
        }

        return configured.getBytes(StandardCharsets.UTF_8);
    }

    public static long tokenExpirationMillis() {
        String configured = System.getProperty("secureshield.token.expiration.ms");

        if (configured == null || configured.isBlank()) {
            configured = System.getenv("SECURESHIELD_TOKEN_EXPIRATION_MS");
        }

        if (configured == null || configured.isBlank()) {
            return DEFAULT_EXPIRATION_MILLIS;
        }

        try {
            long parsed = Long.parseLong(configured);
            return parsed > 0 ? parsed : DEFAULT_EXPIRATION_MILLIS;
        } catch (NumberFormatException ignored) {
            return DEFAULT_EXPIRATION_MILLIS;
        }
    }
}
