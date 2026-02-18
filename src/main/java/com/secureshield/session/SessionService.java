package com.secureshield.session;

import com.secureshield.util.CryptoUtils;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class SessionService {
    private final Map<String, Long> sessions = new ConcurrentHashMap<>();

    public String createSession(long ttlMs) {
        String sessionId = CryptoUtils.base64Encode(CryptoUtils.secureRandomBytes(24));
        sessions.put(sessionId, System.currentTimeMillis() + ttlMs);
        return sessionId;
    }

    public boolean validateSession(String sessionId) {
        Long expiry = sessions.get(sessionId);
        return expiry != null && expiry > System.currentTimeMillis();
    }

    public void revokeSession(String sessionId) {
        sessions.remove(sessionId);
    }
}
