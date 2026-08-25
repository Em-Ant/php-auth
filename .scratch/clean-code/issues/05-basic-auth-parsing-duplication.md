# Basic-auth parsing duplicated

**Severity:** low — three copies of the same block.

The `Authorization: Basic` → `client_id`/`client_secret` extraction block is copy-pasted in `TokenController`, `IntrospectController`, and `RevokeController`.

**Fix:** extract into `ClientAuthenticator` (or a request helper) and call from all three controllers.

## Comments

### 2026-08-21 — Sonar confirmation

SonarCloud flags this as duplicated lines in `TokenController.php` (17 lines, 27.4%) and
`IntrospectController.php` (17 lines, 25.8%). Repository/test duplication is tracked
separately in issue `11-repository-and-test-duplication.md`.

### 2026-08-25 — done

Extracted into `AuthServer\Services\ClientCredentials::mergeFromBasicHeader()`
(static, pure — kept out of `ClientAuthenticator`, which stays authentication-only).
Called from all three controllers. Behavior preserved except one hardening:
body params still win over the header; header parsing itself is unchanged.
Verified: phpstan 5 clean, PHPCS PSR12 clean, PHPUnit 491/491 green,
sonar-php scan + dup gate clean. Row removed from BACKLOG queue.
