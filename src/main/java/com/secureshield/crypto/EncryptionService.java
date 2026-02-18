package com.secureshield.crypto;

import com.secureshield.exception.SecureShieldException;
import com.secureshield.util.CryptoUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class EncryptionService {
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    public String encrypt(String plaintext, SecretKey secretKey) {
        try {
            byte[] iv = CryptoUtils.secureRandomBytes(IV_LENGTH);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
            byte[] cipherText = cipher.doFinal(plaintext.getBytes());

            byte[] combined = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(cipherText, 0, combined, iv.length, cipherText.length);
            return CryptoUtils.base64Encode(combined);
        } catch (Exception e) {
            throw new SecureShieldException("Encryption failed", e);
        }
    }
}
