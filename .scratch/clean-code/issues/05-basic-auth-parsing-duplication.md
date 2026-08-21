# Basic-auth parsing duplicated

**Severity:** low — three copies of the same block.

The `Authorization: Basic` → `client_id`/`client_secret` extraction block is copy-pasted in `TokenController`, `IntrospectController`, and `RevokeController`.

**Fix:** extract into `ClientAuthenticator` (or a request helper) and call from all three controllers.

## Comments

### 2026-08-21 — Sonar confirmation

SonarCloud flags this as duplicated lines in `TokenController.php` (17 lines, 27.4%) and
`IntrospectController.php` (17 lines, 25.8%). Repository/test duplication is tracked
separately in issue `11-repository-and-test-duplication.md`.
