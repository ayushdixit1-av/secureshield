# 🛡️ SecureShield

SecureShield is a beginner-friendly, enterprise-style Java security library with a simple static API and modular internals.

## Features

### 1) Authentication
- JWT access token creation and verification
- JWT refresh token creation
- Access token refresh via refresh token
- Token expiration handling
- Token revocation support
- Token claims extraction
- Token signature/integrity validation
- Refresh token reuse detection

### 2) Password Security
- BCrypt hashing and verification
- Automatic salt handling via BCrypt
- Password policy validation (min length + complexity)
- Breached password list support

### 3) Authorization (RBAC)
- Role definition
- Permission assignment
- Permission verification
- Defaults:
  - `ADMIN` → full access (`*`)
  - `USER` → limited access

### 4) Cryptography
- AES/GCM encryption and decryption
- Secret key generation
- Secure random utility
- Base64 encode/decode
- Constant-time string comparison helper

### 5) Session Management
- Session creation
- Session validation
- Session expiration
- Session revocation

### 6) Attack Protection
- Brute-force mitigation via request limiting
- Replay protection (refresh token reuse detection)
- Token tamper detection (JWT signature verification)
- Timing-safe compare utility

### 7) Rate Limiting
- Per-user request limiting
- Per-IP request limiting
- Default policy: max 100 requests per minute

### 8) Audit Logging
- Login success/failure
- Token creation and verification failure
- Password change event hook available

### 9) Exception Handling
- `SecureShieldException`
- `InvalidTokenException`
- `PasswordMismatchException`
- `AuthenticationException`

### 10) Configuration
Centralized config via `SecureShieldConfig` with system properties and env var overrides for:
- Secret key
- Access/refresh expirations
- Password policy
- Rate limiting policy

## Developer-Friendly API

```java
String token = SecureShield.createToken("user");
boolean ok = SecureShield.verifyToken(token);

String hash = SecureShield.hashPassword("Strong@Pass1");
boolean passOk = SecureShield.verifyPassword("Strong@Pass1", hash);
```

## Enterprise Project Structure

```text
secureshield
├── pom.xml
├── src/main/java/com/secureshield/
│   ├── core/SecureShield.java
│   ├── config/SecureShieldConfig.java
│   ├── jwt/JWTService.java
│   ├── jwt/TokenValidator.java
│   ├── jwt/TokenParser.java
│   ├── password/PasswordService.java
│   ├── password/PasswordValidator.java
│   ├── crypto/EncryptionService.java
│   ├── crypto/DecryptionService.java
│   ├── session/SessionService.java
│   ├── rate/RateLimiter.java
│   ├── audit/AuditLogger.java
│   ├── exception/*.java
│   ├── util/CryptoUtils.java
│   └── model/{TokenClaims,SecurityContext}.java
└── src/test/java/com/secureshield/core/SecureShieldTest.java
```

## Future
- OAuth2
- MFA
- API keys
- Secure cookies
- CSRF protection
- Secure headers
