# AuthenticationOrchestrator god-service

**Severity:** medium — fails the one-sentence test.

`AuthenticationOrchestrator` has 9 dependencies and ~10 responsibilities: login initialization, CSRF validation, authorized-login creation, credential validation, authenticate-login, logout, client-URI lookup, and token parsing/validation. `parseValidToken` is used by `ValidateAccessToken` middleware but lives in an auth service.

**Fix:** move token validation into `TokenService`; consider extracting logout into its own collaborator. Follow-up to the existing split in commit `b308584`.

## Comments

### 2026-08-25 — done

**Deviation from the issue text (deliberate):** `parseValidToken` moved to
`TokenValidator`, *not* `TokenService` — `TokenValidator` already owns validation
and depends on `TokenService`; the issue's suggestion would have created a
circular dependency.

Changes:
- **New `LogoutService`** (`logout`, `validateLogoutRedirectUri`) — RP-Initiated
  Logout extracted verbatim, plus one refactor: redirect-target validation split
  into `clientFromTokenHint()` + `registeredUriOrNull()` to satisfy php:S1142.
  `LogoutController` now depends on it; DI entry added.
- **`TokenValidator::parseValidToken()`** added (validate + throw translation);
  `ValidateAccessToken` middleware depends on `TokenValidator` directly — both
  in `public/index.php` and `TestAppFactory` wiring. Logger injected to keep the
  invalid-token error log.
- **AuthenticationOrchestrator**: 9 deps → 8, logout/token-parse gone; class
  docblock now states its single job (code-flow login lifecycle). The remaining
  cluster (init/csrf/authorized-login/authenticate/credentials/client gating)
  is cohesive around the login flow; further splitting was deliberately not
  done — see "residual" below.
- Tests: 10 logout tests → new `LogoutServiceTest`; `parseValidToken` tests
  rewritten against a real validator in `TokenValidatorTest`;
  `ValidateAccessTokenTest` mocks `TokenValidator`.

Verified: phpstan 0 errors, PHPCS clean, PHPUnit 493/493 green, E2E smoke
171/171, sonar diff dup gate ok. Row removed from BACKLOG queue.

Residual (not ranked): `TokenValidator::validate/verify` and
`LogoutController::logout` still exceed php:S1142's 3-return guideline on
pre-existing lines; `AuthenticationOrchestrator` still has 8 deps if anyone
wants to push the split further (candidate: client gating collaborator).
