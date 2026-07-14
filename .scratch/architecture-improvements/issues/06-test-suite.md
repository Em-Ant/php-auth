# Test suite

**Status: Done**

**PRD:** Architecture Deepening
**Priority:** High

## Problem

Zero test coverage. Login flow, token flow, state machine, keystore, session cookie handling — all untested. No PHPUnit, no test bootstrap, no CI safety net. The architecture work (KeyStore, LoginStateMachine, RedirectUri, InMemorySessionCookieHandler) created seams but no tests.

## Solution

Add PHPUnit 11 + Mockery 2, create test infrastructure, and build coverage from pure units up to full HTTP integration. 9 independently verifiable chunks, each deployable without breaking production.

**Only production code change**: `src/Repositories/DataSource.php` — add `createInstance(PDO)` static factory so integration tests can inject in-memory SQLite. Zero impact on production callers.

---

## Chunk 1 — Test tooling

- [ ] Add `phpunit/phpunit:^11.0` and `mockery/mockery:^2.0` to `composer.json` `require-dev`
- [ ] Create `phpunit.xml.dist` with `Unit` and `Integration` test suites and coverage config (HTML + text)
- [ ] Create `tests/Bootstrap.php` — autoloader, temp dir, key fixtures
- [ ] Add `DataSource::createInstance(\PDO $pdo): void` and make constructor accept optional `?\PDO $pdo = null`
- [ ] Add `composer test` script: `"@php vendor/bin/phpunit"`
- [ ] Verify: `composer test` exits 0

## Chunk 2 — Pure unit tests (no mocking)

- [ ] `tests/Unit/Models/RedirectUriTest.php` — fragment vs query, empty params, special chars
- [ ] `tests/Unit/Base64UtilsTest.php` — encode/decode roundtrip, URL-safe base64
- [ ] `tests/Unit/Response/JsonResponseTest.php` — `create()` and `error()` set correct status/body/content-type/origin
- [ ] `tests/Unit/Models/LoginStatusTest.php` — 4 enum cases
- [ ] `tests/Unit/Models/LoginEventTest.php` — 5 enum cases
- [ ] `tests/Unit/Services/InMemorySessionCookieHandlerTest.php` — read/write/delete, realm mismatch returns null

## Chunk 3 — LoginStateMachine (Mockery: mock for repo, spy for logger)

- [ ] `tests/Unit/Services/LoginStateMachineTest.php` — transition: Authenticate PENDING->AUTHENTICATED
- [ ] Authenticate from wrong status throws `InvalidInputException`
- [ ] Activate AUTHENTICATED->ACTIVE calls `setActive()`
- [ ] Activate from wrong status throws
- [ ] Refresh ACTIVE->calls `refresh()`
- [ ] Refresh from wrong status throws
- [ ] Expire from non-EXPIRED calls `setExpired()`
- [ ] Expire from EXPIRED is no-op
- [ ] CheckExpiry not expired is no-op
- [ ] CheckExpiry expired calls `setExpired()`
- [ ] TTL check: login past TTL throws and expires
- [ ] Logger spy: each event logs expected message

## Chunk 4 — TokenService + SecretsService

- [ ] `tests/Unit/Services/SecretsServiceTest.php` — `generateCode()` UUID format, hash/verify roundtrip, empty config defaults
- [ ] `tests/Unit/Services/TokenServiceTest.php` — `createTokenBundle()` returns correct structure
- [ ] Token JWT claims (iss, aud, sub, exp, iat, jti, session_state, etc.)
- [ ] RS256 signature verifies against public key
- [ ] `at_hash` = MD5 of access token
- [ ] `validateToken()` returns 1 for valid, 0 for bad signature
- [ ] `tokenIsExpired()` false for fresh, true for past-exp token
- [ ] `decodeTokenPayload()` returns associative array
- [ ] `createTokenBundle()` with missing/null KeySet throws

## Chunk 5 — Repository integration tests (in-memory SQLite)

- [ ] `tests/Integration/Repositories/ClientRepositoryTest.php` — findById, findByName (existing + missing)
- [ ] `tests/Integration/Repositories/RealmRepositoryTest.php` — findById, findByName (seeded web/test realms)
- [ ] `tests/Integration/Repositories/UserRepositoryTest.php` — findById, findByEmailAndRealmId
- [ ] `tests/Integration/Repositories/SessionRepositoryTest.php` — create, findById, refresh, setExpired
- [ ] `tests/Integration/Repositories/LoginRepositoryTest.php` — createPending, createAuthenticated, findById, findByCode, findByRefreshToken, setAuthenticated, setActive, refresh, setExpired

## Chunk 6 — AuthorizeService unit tests (heavy mocking)

- [ ] `tests/Unit/Services/AuthorizeServiceTest.php` — `validateRequiredLoginScope()` valid/invalid
- [ ] `initializeLogin()` happy path returns login_id + csrf_token
- [ ] `initializeLogin()` null from repo throws StorageErrorException
- [ ] `validateCsrfToken()` matching passes, mismatch throws
- [ ] `ensureValidSession()` active + valid returns session, expired/null returns null
- [ ] `createAuthorizedLogin()` happy path, invalid redirect_uri throws, user not found throws
- [ ] `ensureValidCredentials()` valid returns user, bad email returns error, wrong password returns error
- [ ] `authenticateLogin()` happy path calls state machine
- [ ] `getTokens()` authorization_code flow returns token bundle
- [ ] `getTokens()` refresh_token flow returns token bundle
- [ ] `getTokens()` unsupported grant_type throws
- [ ] `getTokens()` client requires auth validates secret
- [ ] `logout()` valid id_token expires session, invalid throws
- [ ] `parseValidToken()` valid+not-expired returns payload, invalid throws, expired throws
- [ ] `getClientUri()` found returns URI, missing throws

## Chunk 7 — Full integration flow (Slim app, in-memory SQLite, real keys)

- [ ] `tests/Integration/FullFlowTest.php` — bootstrap Slim stack with test overrides
- [ ] Happy path SSO: GET /auth with valid session cookie -> 302 with code
- [ ] Happy path full login: GET /auth -> login form -> POST login -> code -> POST token -> token bundle
- [ ] PKCE S256: code_challenge + code_verifier workflow
- [ ] PKCE mismatch: wrong verifier -> 400
- [ ] Refresh token: POST /token with refresh_token -> new bundle
- [ ] Refresh token rotation: old token invalid after use
- [ ] Refresh token expired: past-expiry refresh -> 400
- [ ] Logout: GET /logout with valid id_token_hint -> session expired
- [ ] UserInfo: GET /userinfo with Bearer -> sub + preferred_username
- [ ] Certs: GET /certs -> JWKS
- [ ] Well-known: GET /.well-known/openid-configuration -> JSON with realm issuer
- [ ] Invalid client_id -> 400
- [ ] Wrong password -> login form with error
- [ ] CSRF mismatch -> 400
- [ ] Expired authorization code -> 400

## Chunk 8 — Middleware unit tests

- [ ] `tests/Unit/Middleware/CorsMiddlewareTest.php` — OPTIONS -> 204 with CORS headers
- [ ] CorsMiddleware: other methods add headers to response
- [ ] `tests/Unit/Middleware/RealmProviderTest.php` — valid realm sets attribute
- [ ] RealmProvider: invalid realm throws 404
- [ ] `tests/Unit/Middleware/ValidateAccessTokenTest.php` — valid token sets attribute
- [ ] ValidateAccessToken: no header -> 400, invalid token -> 400
- [ ] `tests/Unit/Middleware/RequestLoggerTest.php` — logger spy asserts method/URI/protocol logged

## Chunk 9 — Coverage gap analysis

- [ ] Run `composer test -- --coverage-text --coverage-html=coverage/`
- [ ] Report line/branch/method coverage
- [ ] Target >=80% line, >=85% method
- [ ] Fill gaps: `AuthorizeService` private static helpers scope/startsWith/isEmpty
- [ ] Fill gaps: `TokenService::createTokenBundle()` error paths
- [ ] Fill gaps: `FilesystemKeyStore` file-not-found / malformed key
- [ ] Fill gaps: `DataSource` constructor error handling
- [ ] Final `composer check && composer test` green

## Acceptance criteria

- [ ] `composer test` passes (all chunks merged)
- [ ] Line coverage >=80%
- [ ] Login flow (authorize -> login -> token) fully covered in integration tests
- [ ] Token flow (code + refresh) fully covered
- [ ] State machine all transitions + TTL covered
- [ ] All error paths in login/token flows covered
- [ ] Only production change is `DataSource::createInstance()` (3 lines)
- [ ] Last issue before marking this done: Chunk 9 gap analysis shows >=80%
