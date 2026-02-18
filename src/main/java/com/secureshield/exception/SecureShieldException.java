package com.secureshield.exception;

public class SecureShieldException extends RuntimeException {
    public SecureShieldException(String message) {
        super(message);
    }

    public SecureShieldException(String message, Throwable cause) {
        super(message, cause);
    }
}
