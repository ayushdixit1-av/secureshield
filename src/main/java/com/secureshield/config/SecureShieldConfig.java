package com.secureshield.config;

import java.nio.charset.StandardCharsets;

public final class SecureShieldConfig {
    private static final String DEFAULT_SECRET = "secureshield-enterprise-default-secret-key-please-change";
    private static final long DEFAULT_ACCESS_EXPIRY_MS = 15 * 60 * 1000;
    private static final long DEFAULT_REFRESH_EXPIRY_MS = 24 * 60 * 60 * 1000;
    private static final int DEFAULT_MIN_PASSWORD_LENGTH = 8;
    private static final int DEFAULT_MAX_REQUESTS_PER_MIN = 100;

    public byte[] secretKeyBytes() {
        return read("secureshield.secret", "SECURESHIELD_SECRET", DEFAULT_SECRET).getBytes(StandardCharsets.UTF_8);
    }

    public long accessTokenExpirationMs() {
        return parseLong(read("secureshield.access.expiration.ms", "SECURESHIELD_ACCESS_EXPIRATION_MS", String.valueOf(DEFAULT_ACCESS_EXPIRY_MS)), DEFAULT_ACCESS_EXPIRY_MS);
    }

    public long refreshTokenExpirationMs() {
        return parseLong(read("secureshield.refresh.expiration.ms", "SECURESHIELD_REFRESH_EXPIRATION_MS", String.valueOf(DEFAULT_REFRESH_EXPIRY_MS)), DEFAULT_REFRESH_EXPIRY_MS);
    }

    public int minPasswordLength() {
        return (int) parseLong(read("secureshield.password.min.length", "SECURESHIELD_PASSWORD_MIN_LENGTH", String.valueOf(DEFAULT_MIN_PASSWORD_LENGTH)), DEFAULT_MIN_PASSWORD_LENGTH);
    }

    public int maxRequestsPerMinute() {
        return (int) parseLong(read("secureshield.rate.limit.per.minute", "SECURESHIELD_RATE_LIMIT_PER_MINUTE", String.valueOf(DEFAULT_MAX_REQUESTS_PER_MIN)), DEFAULT_MAX_REQUESTS_PER_MIN);
    }

    private String read(String systemKey, String envKey, String fallback) {
        String value = System.getProperty(systemKey);
        if (value == null || value.isBlank()) {
            value = System.getenv(envKey);
        }
        return (value == null || value.isBlank()) ? fallback : value;
    }

    private long parseLong(String value, long fallback) {
        try {
            long parsed = Long.parseLong(value);
            return parsed > 0 ? parsed : fallback;
        } catch (Exception ignored) {
            return fallback;
        }
    }
}
