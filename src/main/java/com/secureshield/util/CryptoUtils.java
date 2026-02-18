package com.secureshield.util;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public final class CryptoUtils {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private CryptoUtils() {
    }

    public static SecretKey generateAesKey(int bits) {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(bits, SECURE_RANDOM);
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("AES algorithm unavailable", e);
        }
    }

    public static byte[] secureRandomBytes(int length) {
        byte[] bytes = new byte[length];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

    public static String base64Encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] base64Decode(String encoded) {
        return Base64.getDecoder().decode(encoded);
    }

    public static boolean secureEquals(String left, String right) {
        if (left == null || right == null) {
            return false;
        }
        byte[] l = left.getBytes();
        byte[] r = right.getBytes();
        if (l.length != r.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < l.length; i++) {
            result |= l[i] ^ r[i];
        }
        return result == 0;
    }
}
