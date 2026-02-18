package com.secureshield.jwt;

import io.jsonwebtoken.Claims;

import java.util.Set;

public class TokenValidator {
    public boolean isExpired(Claims claims) {
        return claims.getExpiration() == null || claims.getExpiration().before(new java.util.Date());
    }

    public boolean hasExpectedType(Claims claims, String expectedType) {
        return expectedType.equals(claims.get("tokenType", String.class));
    }

    public boolean hasRequiredRole(Claims claims, String role) {
        Object rolesObj = claims.get("roles");
        if (rolesObj instanceof Set<?> set) {
            return set.contains(role);
        }
        if (rolesObj instanceof Iterable<?> iterable) {
            for (Object item : iterable) {
                if (role.equals(String.valueOf(item))) {
                    return true;
                }
            }
        }
        return false;
    }
}
