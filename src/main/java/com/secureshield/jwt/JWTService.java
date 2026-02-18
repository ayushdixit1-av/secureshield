package com.secureshield.jwt;

import com.secureshield.config.SecureShieldConfig;
import com.secureshield.exception.InvalidTokenException;
import com.secureshield.model.TokenClaims;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Date;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class JWTService {
    private static final String ACCESS = "access";
    private static final String REFRESH = "refresh";

    private final Key key;
    private final long accessTokenExpiryMs;
    private final long refreshTokenExpiryMs;
    private final TokenValidator tokenValidator = new TokenValidator();
    private final TokenParser tokenParser = new TokenParser();

    private final Set<String> revokedTokenIds = ConcurrentHashMap.newKeySet();
    private final Set<String> usedRefreshTokenIds = ConcurrentHashMap.newKeySet();

    public JWTService(SecureShieldConfig config) {
        this.key = Keys.hmacShaKeyFor(config.secretKeyBytes());
        this.accessTokenExpiryMs = config.accessTokenExpirationMs();
        this.refreshTokenExpiryMs = config.refreshTokenExpirationMs();
    }

    public String createAccessToken(String username, Set<String> roles) {
        return createToken(username, ACCESS, roles, accessTokenExpiryMs);
    }

    public String createRefreshToken(String username, Set<String> roles) {
        return createToken(username, REFRESH, roles, refreshTokenExpiryMs);
    }

    public String refreshAccessToken(String refreshToken) {
        Claims claims = parseSignedClaims(refreshToken);
        if (!tokenValidator.hasExpectedType(claims, REFRESH)) {
            throw new InvalidTokenException("Not a refresh token");
        }

        String tokenId = claims.getId();
        if (usedRefreshTokenIds.contains(tokenId)) {
            throw new InvalidTokenException("Refresh token reuse detected");
        }
        usedRefreshTokenIds.add(tokenId);

        return createAccessToken(claims.getSubject(), extractRoles(claims));
    }

    public boolean verifyToken(String token) {
        try {
            Claims claims = parseSignedClaims(token);
            return !tokenValidator.isExpired(claims) && !revokedTokenIds.contains(claims.getId());
        } catch (Exception ex) {
            return false;
        }
    }

    public void revokeToken(String token) {
        Claims claims = parseSignedClaims(token);
        revokedTokenIds.add(claims.getId());
    }

    public TokenClaims extractClaims(String token) {
        Claims claims = parseSignedClaims(token);
        if (revokedTokenIds.contains(claims.getId())) {
            throw new InvalidTokenException("Token is revoked");
        }
        return tokenParser.parse(claims);
    }

    private String createToken(String username, String tokenType, Set<String> roles, long expiryMs) {
        if (username == null || username.isBlank()) {
            throw new InvalidTokenException("Username is required");
        }

        Date now = new Date();
        return Jwts.builder()
                .setSubject(username)
                .setId(UUID.randomUUID().toString())
                .claim("tokenType", tokenType)
                .claim("roles", roles)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + expiryMs))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    private Claims parseSignedClaims(String token) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
        } catch (Exception e) {
            throw new InvalidTokenException("Invalid token");
        }
    }

    @SuppressWarnings("unchecked")
    private Set<String> extractRoles(Claims claims) {
        Object roles = claims.get("roles");
        if (roles instanceof Set<?> set) {
            return (Set<String>) set;
        }
        java.util.Set<String> out = new java.util.HashSet<>();
        if (roles instanceof Iterable<?> iterable) {
            for (Object item : iterable) {
                out.add(String.valueOf(item));
            }
        }
        return out;
    }
}
