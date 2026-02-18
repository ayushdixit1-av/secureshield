# 🛡️ SecureShield

SecureShield is a beginner-friendly, enterprise-style Java security library with a simple static API and modular internals.

## ✅ Current status
- Unit-tested security library API
- Maven-ready project metadata (sources + javadocs artifacts)
- Sonatype release profile included for Maven Central publishing

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
- Access-token / refresh-token specific verification APIs

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
- Temporary account lock after repeated failures
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
- Max login attempts and lock duration

## Quick Start

```java
import com.secureshield.core.SecureShield;

String accessToken = SecureShield.createToken("user");
boolean valid = SecureShield.verifyAccessToken(accessToken);

String hash = SecureShield.hashPassword("Strong@Pass1");
boolean passwordOk = SecureShield.verifyPassword("Strong@Pass1", hash);
```

## Maven dependency (after publish)

```xml
<dependency>
  <groupId>com.secureshield</groupId>
  <artifactId>secureshield</artifactId>
  <version>1.0.0</version>
</dependency>
```

## Project Structure

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
│   ├── attack/BruteForceProtector.java
│   ├── audit/AuditLogger.java
│   ├── exception/*.java
│   ├── util/CryptoUtils.java
│   └── model/{TokenClaims,SecurityContext}.java
└── src/test/java/com/secureshield/core/SecureShieldTest.java
```

## Publish to Maven Central

> Prerequisites: Sonatype account, approved namespace (`com.secureshield`), GPG key, and credentials in Maven settings.

### 1) Configure `~/.m2/settings.xml`

```xml
<settings>
  <servers>
    <server>
      <id>ossrh</id>
      <username>${env.OSSRH_USERNAME}</username>
      <password>${env.OSSRH_TOKEN}</password>
    </server>
  </servers>
</settings>
```

### 2) Import your GPG key

```bash
gpg --list-secret-keys
```

### 3) Run local checks

```bash
mvn clean test
```

### 4) Publish signed artifacts using release profile

```bash
mvn -Prelease clean deploy
```

This project already attaches:
- binary JAR
- sources JAR
- javadocs JAR
- GPG signatures (in `release` profile)

## Is this enterprise-ready today?
Good baseline ✅, but for strict enterprise production you should still add:
1. Persistent stores (revoked tokens, sessions, rate-limits) via Redis/DB.
2. Key rotation + KMS/HSM support.
3. Distributed audit pipeline + tamper-evident logs.
4. OAuth2/OIDC + MFA flows.
5. Security headers / CSRF helpers for web integrations.
6. Observability (metrics/tracing) and threat analytics.

## License
MIT
