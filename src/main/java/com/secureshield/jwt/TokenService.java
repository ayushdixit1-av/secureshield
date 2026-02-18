package com.secureshield.jwt;

import com.secureshield.config.SecureShieldConfig;
import com.secureshield.model.TokenClaims;

import java.util.Set;

/**
 * @deprecated Use {@link JWTService}. Kept for backwards compatibility.
 */
@Deprecated
public class TokenService {

    private final JWTService jwtService;

    public TokenService() {
        this.jwtService = new JWTService(new SecureShieldConfig());
    }

    public String createToken(String username) {
        return jwtService.createAccessToken(username, Set.of("USER"));
    }

    public boolean verifyToken(String token) {
        return jwtService.verifyToken(token);
    }

    public String extractUsername(String token) {
        TokenClaims claims = jwtService.extractClaims(token);
        return claims.subject();
    }
}
