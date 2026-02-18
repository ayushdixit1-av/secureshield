package com.secureshield.jwt;

import com.secureshield.model.TokenClaims;
import io.jsonwebtoken.Claims;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

public class TokenParser {
    @SuppressWarnings("unchecked")
    public TokenClaims parse(Claims claims) {
        Object rolesObj = claims.get("roles");
        Set<String> roles = new HashSet<>();
        if (rolesObj instanceof Iterable<?> iterable) {
            for (Object item : iterable) {
                roles.add(String.valueOf(item));
            }
        }

        return new TokenClaims(
                claims.getSubject(),
                claims.getId(),
                claims.get("tokenType", String.class),
                roles,
                claims.getIssuedAt() == null ? new Date() : claims.getIssuedAt(),
                claims.getExpiration()
        );
    }
}
