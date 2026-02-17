package com.secureshield.core;

public class SecureShield {

    private static final String SECRET = "secureshield-secret";

    public static String createToken(String username) {
        long time = System.currentTimeMillis();
        return username + ":" + time + ":" + SECRET;
    }

    public static boolean verifyToken(String token) {

        if (token == null) return false;

        String[] parts = token.split(":");

        if (parts.length != 3) return false;

        return SECRET.equals(parts[2]);
    }

}
