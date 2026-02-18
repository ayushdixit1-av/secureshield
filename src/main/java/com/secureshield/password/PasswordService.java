package com.secureshield.password;

import com.secureshield.exception.PasswordMismatchException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class PasswordService {
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private final PasswordValidator validator;

    public PasswordService(PasswordValidator validator) {
        this.validator = validator;
    }

    public String hashPassword(String rawPassword) {
        validator.validate(rawPassword);
        return passwordEncoder.encode(rawPassword);
    }

    public boolean verifyPassword(String rawPassword, String hashedPassword) {
        return rawPassword != null && hashedPassword != null && passwordEncoder.matches(rawPassword, hashedPassword);
    }

    public void verifyOrThrow(String rawPassword, String hashedPassword) {
        if (!verifyPassword(rawPassword, hashedPassword)) {
            throw new PasswordMismatchException("Password verification failed");
        }
    }
}
