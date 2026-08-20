# OIDC Compliance — prioritized fix plan

**Status:** done — P0 (F-21…F-26) and all P1 fixes (F-27…F-34) implemented,
regression-tested and e2e-verified. Keycloak-parity items (opportunistic) are
split out to `.scratch/keycloak-parity/PRD.md`.
**Owner:** agent + user
**Depends on:** nothing (isolated); some fixes touch `TokenGrantService` /
`AuthenticationOrchestrator`, which other workstreams also touch

## Problem Statement

A full audit of the OIDC surface (read of `src/`, `public/`, `static/`,
`migrations/` + live probing of every endpoint on a dev server) found:

- **6 security bugs** — including three that break token/realm binding, two of
  which are reproducible attacks (redeem someone else's code with a different
  client; redeem a code from realm A at realm B).
- **9 OIDC spec deviations** — several are RFC *MUST*s (error codes,
  `Cache-Control: no-store`, revocation 401, `response_type` rejection).
- **~11 Keycloak-parity gaps** — mostly minor, by design a subset not a clone.
  Split out to `.scratch/keycloak-parity/PRD.md`.

Nothing found here breaks the happy-path flows (the e2e suite passes), but the
security items are all in *validation gaps on untrusted input* — exactly the
class that turns into exploits.

## Current State (verified)

Every row below was reproduced over HTTP against a running dev server
(`php -S` + `router.php`) unless noted `(code)`.

| # | Finding | Severity | Where |
|---|---------|----------|-------|
| S-01 | Authorization code not bound to its client or `redirect_uri` — code issued to `kc_app` redeemed by `local` with a different redirect | **Critical** | `TokenGrantService::getTokensByCode`, `LoginRepository::findByCode` |
| S-02 | Refresh token not bound to its client — `kc_app` RT refreshed by `local` | **Critical** | `TokenGrantService::getTokensByRefreshToken` |
| S-03 | Cross-realm code redemption — `test` code redeemed at `/realms/web` (signed with web key, `sub` of test user) | **Critical** | global `findByCode`/`findByRefreshToken`; realm used only for signing |
| S-04 | `AUTH_SESSION` cookie not `HttpOnly` — JS-readable SSO cookie | High | `HttpSessionCookieHandler::buildSetCookie` |
| S-05 | `/login-status-iframe.html/init` returns 200 for any client/origin — cross-origin session probing | High | `public/index.php:188`, `login-iframe.html:47` |
| S-06 | Failed refresh permanently expires a valid refresh token (one bad attempt = DoS) | Med | `TokenGrantService.php:190-194` |
| D-01 | Token/auth/logout error code is `"Invalid request"` (uppercase, space) instead of RFC 6749 §5.2 codes; unknown client → 400 not 401 — ✅ fixed by F-27 | Med | `TokenController`, `AuthorizationController`, `LogoutController` |
| D-02 | No `Cache-Control: no-store` / `Pragma: no-cache` on token responses (RFC 6749 §5.1 MUST) — ✅ fixed by F-28 | Med | `JsonResponse::create` |
| D-03 | `response_type` never validated — `token`, `id_token token`, `code token`, `none` all treated as `code` — ✅ fixed by F-29 | Med | `InputValidator::validateQueryParams` |
| D-04 | `nonce`, `state`, `response_mode` unconditionally required for the code flow (all OPTIONAL in OIDC §3.1.2.1) — ✅ fixed by F-31 | Low | `InputValidator::validateQueryParams` |
| D-05 | `prompt=login` / `prompt=consent` ignored (SSO session reused; no consent screen) — ✅ `prompt=login` fixed by F-32; `prompt=consent` remains a documented non-goal until F-10 | Low | `AuthorizationController.php:60,97` |
| D-06 | `redirect_uri` matching too permissive (prefix + trailing-slash normalization) — ✅ fixed by F-33 | Med | `InputValidator::validateRedirectUri` |
| D-07 | Revocation silently 200 on failed client auth (RFC 7009 §2.2 requires 401) — ✅ fixed by F-30 | Med | `RevokeController`, `TokenRevocationService:48` |
| D-08 | Discovery: `scope_supported` should be `scopes_supported` (RFC 8414 §2) — ✅ fixed by F-34 | Low | `static/well-known.json:76` |
| D-09 | Discovery over-advertises: `request_parameter_supported`, `require_request_uri_registration`, `tls_client_certificate_bound_access_tokens`, `frontchannel_logout_supported`, `subject_types_supported:[pairwise]` — none implemented — ✅ fixed by F-34 | Low | `static/well-known.json` |

**Verified compliant** (keep as regression anchors): `at_hash` (left half
SHA-256, b64url); ID-token core claims (`iss`, `sub`, `aud`, `azp`, `exp`,
`iat`, `auth_time`, `nonce`, `at_hash`, `sid`, `session_state`); single-use
codes; refresh rotation; `prompt=none` both branches; logout redirect
validation; introspect `invalid_client` 401 + `active:false` for garbage;
`client_credentials` token shape (`not-before-policy`, `allowed-origins`,
`realm_access`).

## Goals

1. Close all six security findings (S-01…S-06) — hard invariants, regression-tested. ✅ done (F-21…F-26).
2. Make the error surface RFC-compliant (D-01, D-02, D-07) and reject
   unsupported `response_type` (D-03). ✅ done (F-27…F-30).
3. Tighten validation to match the OIDC spec's *optional* semantics (D-04, D-05,
   D-06) and make the discovery doc truthful (D-08, D-09). ✅ done (F-31…F-34).

## Prioritized fixes

### P0 — Security (do first; preempts other work per BACKLOG policy)

| Ref | Fix | Acceptance | Files |
|-----|-----|-----------|-------|
| F-21 | **Bind auth code to client + redirect_uri.** `getTokensByCode` must verify `login.client_id === $client->getId()` and `login.redirect_uri === $requested redirect_uri`; reject with `invalid_grant`. | Redeeming client B's code with client A fails; wrong redirect fails. ✅ done (CodeBindingTest + e2e Step 2b) | `TokenGrantService`, `LoginRepository` (add findByCode scoped to client/redirect, or compare after fetch) |
| F-22 | **Bind refresh token to client.** `getTokensByRefreshToken` must verify `login.client_id === $client->getId()` (mirror the check revoke already has). | Client A's RT refreshed by client B → `invalid_grant`. | `TokenGrantService` |
| F-23 | **Enforce realm isolation.** Code/refresh lookups must be scoped to the request realm (e.g. `findByCode($code, $realm_id)` via `JOIN clients`/`sessions` realm check). | Code minted in realm A is not redeemable at realm B. ✅ done (`LoginRepositoryTest` realm-scoping tests + `CodeBindingTest::testCodeNotRedeemableInAnotherRealm` + e2e Step 2b) | `LoginRepository`, `TokenGrantService` |
| F-24 | **`HttpOnly` on the SSO cookie** + separate non-HttpOnly check-session cookie (Keycloak splits these; the iframe must read the check cookie, not the session cookie). | `AUTH_SESSION` not readable from JS; check-session still works. | `HttpSessionCookieHandler`, `login-iframe.html` |
| F-25 | **Validate client + origin in `/login-status-iframe.html/init`** (client exists in realm, origin matches registered URI) before signaling `ok`. | `?client_id=evil&origin=https://evil.com` → error. | `public/index.php:188`, `AuthenticationOrchestrator` |
| F-26 | **Don't expire the login on failed refresh.** A failed token validation must not mutate state (only an *authorized* Expire path may). | Bad/wrong-realm refresh attempt leaves the RT usable at the correct endpoint. | `TokenGrantService.php:190-194`, `LoginStateMachine` |

### P1 — OIDC spec deviations (RFC MUSTs first)

| Ref | Fix | Acceptance |
|-----|-----|-----------|
| F-27 | **Compliant error codes + statuses.** Token/auth/logout/introspect return RFC 6749 §5.2 codes (`invalid_request`, `invalid_client`→401, `invalid_grant`, `unsupported_grant_type`, `invalid_scope`). ✅ done (`OAuth2Error`, e2e Step 6b) | e2e + curl assert lowercase codes and 401 for bad client. |
| F-28 | **`Cache-Control: no-store` + `Pragma: no-cache` on every response containing tokens/credentials** (token, introspect, revoke, userinfo). ✅ done (`JsonResponse::create`) | Headers present; curl-asserted. |
| F-29 | **Reject `response_type != code`** with `unsupported_response_type` (redirect to validated redirect_uri when possible, else error page). ✅ done (`InputValidator`, e2e Step 6b) | `response_type=token`/hybrid/`none` rejected. |
| F-30 | **Revocation 401 on failed client auth** (RFC 7009 §2.2). ✅ done (`TokenRevocationService` throws `invalid client`, `RevokeController` → 401) | Bad client → 401 `invalid_client`. |
| F-31 | **Make `nonce`/`state`/`response_mode` optional for the code flow** (nonce still enforced when response_type is implicit/hybrid — which is rejected anyway). ✅ done (`InputValidator` + `AuthenticationOrchestrator::loginFields` defaults) | Code flow without nonce/state/response_mode succeeds; defaults apply. |
| F-32 | **`prompt=login` forces re-auth** (session not reused); `prompt=consent` → at least a documented non-goal until the consent screen (F-10) lands. ✅ done (`AuthorizationController` gates session reuse on `prompt !== 'login'`) | SSO session + `prompt=login` → login form. |
| F-33 | **Exact `redirect_uri` matching** (drop prefix/trailing-slash normalization; registered URI matched exactly). ✅ verified live — Keycloak uses exact match, no implicit prefix/sub-path/query; wildcards only when explicitly registered. ✅ done (`InputValidator::validateRedirectUri` exact match). ⚠️ Extended by F-44 (explicit `*` wildcard opt-in) — see implementation note below. | Sub-path redirect rejected; exact matches pass. |
| F-34 | **Truthful discovery**: rename `scope_supported`→`scopes_supported`; set `request_parameter_supported`/`request_uri`/mTLS/front-channel/pairwise to false (or implement). ✅ done (`static/well-known.json`) | Doc matches implemented surface. |

## Non-goals / consciously deferred

- **Implicit & hybrid flows** (`response_type=token`, `id_token`, `code token`,
  etc.) — will *reject* them (F-29) but never implement. Stays `code`-only.
- **`request`/`request_uri` (JAR), mTLS, pairwise subjects, front-channel logout
  execution** — advertised as false (F-34 done); no implementation planned.
- **Keycloak parity** (claim/mapper model, `x5t`, `session_state` iframe,
  sliding timeout, `acr`, userinfo scopes, `nonce` in tokens, deferred batch) —
  tracked in `.scratch/keycloak-parity/PRD.md`.
- **Consent screen** — owned by F-10 (`token-lifecycle`/consent); F-32 only
  ensures `prompt=consent` isn't silently *ignored*.
- **Blacklist purge** (P-10) — already tracked as F-19 (`token-lifecycle`).

## Acceptance (whole PRD)

1. S-01…S-06 have regression tests (integration + e2e) that fail on the current
   code and pass after.
2. `composer check` green; error-surface assertions added to e2e (`bin/e2e-test.sh`).
3. Discovery doc matches the implemented surface 1:1.
4. No behavioral regression in the happy-path e2e flow.

## Implementation notes — P1 batch (F-27…F-34)

All eight P1 fixes shipped together (one working session, 2026-08-19); P0
(F-21…F-26) shipped earlier. Verification for the P1 batch:

- **Error surface (F-27/F-29):** new `src/Exceptions/OAuth2Error` carries RFC
  6749 §5.2 `error` code + HTTP status (extends `ValidationFailed` so existing
  catch blocks keep working); controllers catch it first and emit
  `error_code`/`error_description`. Mapping: `invalid_client` → 401 (incl.
  unknown client / wrong secret), `invalid_grant` for code/refresh/PKCE
  failures (RFC 7636 §4.6), `unsupported_grant_type` for unknown flows,
  `unsupported_response_type` for `response_type != code` (F-29),
  `invalid_scope` via `ScopeResolver`. `TokenController` now runs `getTokens`
  before the `getClientUri` origin computation so a bad client produces the
  correct 401 instead of a generic validation error.
- **Cache headers (F-28):** `JsonResponse::create` sets `Cache-Control:
  no-store` + `Pragma: no-cache` on every JSON response (token/introspect/
  revoke/userinfo all route through it).
- **Revocation 401 (F-30):** `TokenRevocationService` throws
  `AuthenticationFailed('invalid client')` on failed client auth;
  `RevokeController` maps it to 401 `invalid_client` (RFC 7009 §2.2).
- **Optional code-flow params (F-31):** `InputValidator::validateQueryParams`
  no longer requires `nonce`/`state`/`response_mode`; `AuthenticationOrchestrator`
  applies defaults (`state`/`nonce` = `''`, `response_mode` = `query`) via the
  `loginFields` helper when creating the login row.
- **`prompt=login` (F-32):** `AuthorizationController::authorize` only reuses
  the SSO session when `prompt !== 'login'`; `prompt=login` always renders the
  login form.
- **Exact `redirect_uri` (F-33):** `InputValidator::validateRedirectUri`
  requires an exact match of the registered URI (no prefix/sub-path/trailing
  slash normalization); logout validation updated to match.
- **Discovery (F-34):** `static/well-known.json` now truthful —
  `scopes_supported`, `subject_types_supported` only `public`, front-channel /
  request / request_uri / mTLS / pairwise all `false`.

**F-44 — Keycloak-style `*` wildcard opt-in (P0, 2026-08-20):** F-33's exact
match broke the intentional sub-path login flow, so an explicit opt-in was
restored. `InputValidator::validateRedirectUri` now accepts a trailing `*` on
the registered URI (semantics verified live, keycloak-parity Q3): the
scheme/host/port must match **exactly** (the wildcard never crosses origins —
mirrors the Keycloak 26.6.3 hostname fix), the requested path may be any depth
under the registered prefix, query strings are allowed, zero-length-after-slash
matches, and sibling paths/hosts are rejected. Origins are extracted strictly:
malformed authorities (non-numeric ports like `localhost:5173x`, or userinfo)
are rejected — parse_url silently truncates `localhost:5173x` to port 5173,
the same parser-mismatch class as Keycloak CVE-2026-7504. **Iframe allowlist
impact:** none — because the wildcard is path-scoped only, `validateClientOrigin`
is unaffected (origins carry no path); locked with unit + e2e tests. Seed URIs
migrated: `local` → `http://localhost:5173/*`, `playground` →
`http://localhost:5173/react-playground/*`; `kc_app` stays exact (F-33
regression anchor). `getClientUri` (token CORS fallback) now returns the
origin, not the full URI, which would be an invalid `Access-Control-Allow-Origin`.
Tests: 452 OK, `composer check` green.

**Quality gates:** `composer test` 430 OK, `composer stan` (level 5) OK,
`composer cs_check` (PSR12) OK, sonar-php gate (`--diff-ref=HEAD
--fail-on-dup=3.0`) exit 0, `composer test:e2e` exit 0 (146 checks). The e2e
script now also asserts each P1 fix: Step 1b discovery truthfulness (F-34),
Step 2c `prompt=login` forces re-auth with a valid SSO session (F-32, session
cookie injected manually since it is Secure and cannot round-trip plain http),
Step 3b `Cache-Control: no-store`/`Pragma` on the token response (F-28),
Step 6c code flow without nonce/state/response_mode (F-31), Step 6d sub-path
`redirect_uri` rejected (F-33), plus the existing Step 6b error-surface
assertions (F-27/F-29) and the revocation 401 check (F-30).