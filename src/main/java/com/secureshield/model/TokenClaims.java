package com.secureshield.model;

import java.util.Date;
import java.util.Set;

public record TokenClaims(String subject, String tokenId, String tokenType, Set<String> roles, Date issuedAt, Date expiration) {
}
