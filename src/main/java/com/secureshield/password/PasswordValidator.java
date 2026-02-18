package com.secureshield.password;

import com.secureshield.config.SecureShieldConfig;
import com.secureshield.exception.AuthenticationException;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class PasswordValidator {
    private final SecureShieldConfig config;
    private final Set<String> breachedPasswords = ConcurrentHashMap.newKeySet();

    public PasswordValidator(SecureShieldConfig config) {
        this.config = config;
        breachedPasswords.add("password");
        breachedPasswords.add("12345678");
        breachedPasswords.add("qwerty123");
    }

    public void validate(String password) {
        if (password == null || password.length() < config.minPasswordLength()) {
            throw new AuthenticationException("Password does not meet minimum length policy");
        }
        if (!hasComplexity(password)) {
            throw new AuthenticationException("Password must include uppercase, lowercase, digit, and symbol");
        }
        if (breachedPasswords.contains(password.toLowerCase())) {
            throw new AuthenticationException("Password appears in known breach list");
        }
    }

    public void addBreachedPassword(String breached) {
        if (breached != null) {
            breachedPasswords.add(breached.toLowerCase());
        }
    }

    private boolean hasComplexity(String password) {
        boolean upper = false, lower = false, digit = false, symbol = false;
        for (char ch : password.toCharArray()) {
            if (Character.isUpperCase(ch)) upper = true;
            else if (Character.isLowerCase(ch)) lower = true;
            else if (Character.isDigit(ch)) digit = true;
            else symbol = true;
        }
        return upper && lower && digit && symbol;
    }
}
