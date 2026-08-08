# Token validation knowledge duplicated

**Severity:** low.

Token decoding/validation is spread across `TokenGrantService`, `TokenIntrospectionService`, `TokenRevocationService`, and `AuthenticationOrchestrator` with subtly different claim checks — expiry checked as `tokenIsExpired()` in some places, `exp < time()` in others; audience/issuer never validated consistently.

**Fix:** centralize claim validation (signature, exp, aud, iss, typ, blacklist) behind one `TokenService`/`TokenValidator` method so all four flows share the same policy.

## Comments

### 2026-08-09 — done

Centralized via new `src/Services/TokenValidator.php` (`validate(token, realm, ?expected_typ, ?expected_aud)`: decode → signature → typ → iss → exp → aud→ azp fallback → jti blacklist). All four flows now call it:

- `TokenGrantService::getTokensByRefreshToken` — `expected_typ: 'Refresh'` (replaces `tokenIsExpired`)
- `AuthenticationOrchestrator::parseValidToken` — `expected_typ: 'Bearer'` (userinfo)
- `AuthenticationOrchestrator::logout` — `validateIdTokenHint` (no expiry; spec-aligned, see below)
- `TokenIntrospectionService::introspect` — no typ (stays cross-client), one combined decode/signature/exp/blacklist path
- `TokenRevocationService::revoke` (access) — `expected_typ: 'Bearer'` + expected audience = client name

Removed the divergence: `TokenService::tokenIsExpired()` and both inline `exp < time()` checks in the introspection service. `ValidateAccessToken` middleware no longer duplicates the blacklist check. `TokenValidator` wired in `Definitions.php`; `TokenService::decodeTokenSafely` still the low-level decode primitive.

Behavior tightened per policy (requested): revoking a no-longer-valid token no-ops; tokens with a foreign `iss` rejected everywhere.

### 2026-08-09 — logout re-scoped (OIDC RP-Initiated Logout 1.0 §2.x/§4)

The uniform policy wrongly rejected expired `id_token_hint`s; the spec requires the OP to verify it issued the token (signature, `iss`, `typ`) but **accepts expired hints** when `sid` maps to a current/recent session, and treats logout as idempotent ("not an error if the end-user isn't logged in"). `SessionRepository::setExpired` is already idempotent for unknown sessions.

New `TokenValidator::validateIdTokenHint()` — signature, `iss`, `typ === 'ID'`, `jti` blacklist, **no expiry check**; `AuthenticationOrchestrator::logout` switched to it. Expiry stays enforced in `validate()` for grant/userinfo/introspect/revoke.

Coverage: `TokenValidatorTest` (17 unit cases incl. expired-ID-hint accepted, non-ID/tampered/foreign-issuer rejected), `TokenPolicyTest` (expired hint logs out → session actually gone), `AuthenticationOrchestratorTest` / `ValidateAccessTokenTest` / `TokenServiceTest` updated. Suite 324 green; PHPStan 5 green; PHPCS PSR12 green; e2e 36/36.
