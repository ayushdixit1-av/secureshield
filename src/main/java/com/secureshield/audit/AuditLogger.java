package com.secureshield.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuditLogger {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuditLogger.class);

    public void loginSuccess(String username) {
        LOGGER.info("SECURITY_EVENT login_success user={}", username);
    }

    public void loginFailure(String username) {
        LOGGER.warn("SECURITY_EVENT login_failure user={}", username);
    }

    public void tokenCreated(String username) {
        LOGGER.info("SECURITY_EVENT token_created user={}", username);
    }

    public void tokenVerificationFailure(String reason) {
        LOGGER.warn("SECURITY_EVENT token_verification_failure reason={}", reason);
    }

    public void passwordChanged(String username) {
        LOGGER.info("SECURITY_EVENT password_change user={}", username);
    }
}
