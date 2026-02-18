package com.secureshield.util;

import com.secureshield.config.SecureShieldConfig;

/**
 * @deprecated Use {@link SecureShieldConfig}. Kept for backwards compatibility.
 */
@Deprecated
public final class SecurityConfig {

    private static final SecureShieldConfig CONFIG = new SecureShieldConfig();

    private SecurityConfig() {
    }

    public static byte[] secretKeyBytes() {
        return CONFIG.secretKeyBytes();
    }

    public static long tokenExpirationMillis() {
        return CONFIG.accessTokenExpirationMs();
    }
}
