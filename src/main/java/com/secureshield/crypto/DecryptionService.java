package com.secureshield.crypto;

import com.secureshield.exception.SecureShieldException;
import com.secureshield.util.CryptoUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.util.Arrays;

public class DecryptionService {
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    public String decrypt(String encryptedPayload, SecretKey secretKey) {
        try {
            byte[] decoded = CryptoUtils.base64Decode(encryptedPayload);
            byte[] iv = Arrays.copyOfRange(decoded, 0, IV_LENGTH);
            byte[] cipherText = Arrays.copyOfRange(decoded, IV_LENGTH, decoded.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
            return new String(cipher.doFinal(cipherText));
        } catch (Exception e) {
            throw new SecureShieldException("Decryption failed", e);
        }
    }
}
