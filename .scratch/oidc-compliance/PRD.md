# OIDC Compliance & Keycloak Parity — prioritized fix plan

**Status:** open — review done, fixes ranked, not started
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
- **~11 Keycloak-parity gaps** — mostly minor. These were **by design a subset**
  (deliberate: this server is a functional subset of Keycloak, not a clone), so
  parity items are ranked lower and are opportunistic.

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
| D-01 | Token/auth/logout error code is `"Invalid request"` (uppercase, space) instead of RFC 6749 §5.2 codes; unknown client → 400 not 401 | Med | `TokenController`, `AuthorizationController`, `LogoutController` |
| D-02 | No `Cache-Control: no-store` / `Pragma: no-cache` on token responses (RFC 6749 §5.1 MUST) | Med | `JsonResponse::create` |
| D-03 | `response_type` never validated — `token`, `id_token token`, `code token`, `none` all treated as `code` | Med | `InputValidator::validateQueryParams` |
| D-04 | `nonce`, `state`, `response_mode` unconditionally required for the code flow (all OPTIONAL in OIDC §3.1.2.1) | Low | `InputValidator::validateQueryParams` |
| D-05 | `prompt=login` / `prompt=consent` ignored (SSO session reused; no consent screen) | Low | `AuthorizationController.php:60,97` |
| D-06 | `redirect_uri` matching too permissive (prefix + trailing-slash normalization) | Med | `InputValidator::validateRedirectUri` |
| D-07 | Revocation silently 200 on failed client auth (RFC 7009 §2.2 requires 401) | Med | `RevokeController`, `TokenRevocationService:48` |
| D-08 | Discovery: `scope_supported` should be `scopes_supported` (RFC 8414 §2) | Low | `static/well-known.json:76` |
| D-09 | Discovery over-advertises: `request_parameter_supported`, `require_request_uri_registration`, `tls_client_certificate_bound_access_tokens`, `frontchannel_logout_supported`, `subject_types_supported:[pairwise]` — none implemented | Low | `static/well-known.json` |
| P-01 | `session_state` = raw session id (Keycloak: salted SHA-256) | Low | `AuthorizationController`, `TokenService` |
| P-02 | `acr` hardcoded `"0"` (Keycloak reports `1` for password auth) | Low | `SessionOrchestrator::create`, schema default |
| P-03 | JWKS `x5t` / `x5t#sha256` = b64url of the *hex* fingerprint (RFC 7517 §4.7 requires b64url of binary thumbprint) | Med | `TokenService::createKeys` |
| P-04 | `nonce` embedded in access & refresh tokens (Keycloak: ID token only) | Low | `TokenService` |
| P-05 | Idle session timeout never slides — measured from `created_at`, ignores `updated_at` | Med | `SessionOrchestrator::checkExpiry` |
| P-06 | userinfo returns only `sub` + `preferred_username` regardless of scope; `claims_supported` advertises more | Low | `OidcController::sendUserInfo` |
| P-07 | Optional auth-request params ignored: `login_hint`, `max_age`, `acr_values`, `ui_locales`, `display`, `claims` | Low | `AuthorizationController` |
| P-08 | userinfo missing-token → 400; no `WWW-Authenticate` on 401s | Low | `ValidateAccessToken` |
| P-09 | `X-Powered-By: PHP/8.3.6` leaked | Low | Slim/PHP default |
| P-10 | Token blacklist never purged (unbounded growth) | Low | `TokenBlacklistRepository` |

**Verified compliant** (keep as regression anchors): `at_hash` (left half
SHA-256, b64url); ID-token core claims (`iss`, `sub`, `aud`, `azp`, `exp`,
`iat`, `auth_time`, `nonce`, `at_hash`, `sid`, `session_state`); single-use
codes; refresh rotation; `prompt=none` both branches; logout redirect
validation; introspect `invalid_client` 401 + `active:false` for garbage;
`client_credentials` token shape (`not-before-policy`, `allowed-origins`,
`realm_access`).

## The model — stance on Keycloak parity

- **Functional subset, not a clone.** Keycloak parity was a *design decision*,
  not a debt item: this server implements the subset of Keycloak's OIDC surface
  that the product needs (auth-code + client-credentials, refresh/introspect/
  revoke/logout, PKCE-S256, check-session iframe). Parity items in this PRD are
  ranked below spec compliance and are **opportunistic** — do them when they
  intersect feature work, don't block on them.
- **The only parity items that matter now** are the ones that *break real
  Keycloak clients* or *leak secrets*: `x5t` (breaks JWKS thumbprint
  verification), `session_state` format (breaks check-session iframe against
  clients that compute the salted hash), sliding idle timeout (breaks SSO
  lifetime expectations).
- **Spec compliance is mandatory.** RFC 6749 / OIDC Core *MUST*s are not
  negotiable and outrank every parity item.

## Goals

1. Close all six security findings (S-01…S-06) — hard invariants, regression-tested.
2. Make the error surface RFC-compliant (D-01, D-02, D-07) and reject
   unsupported `response_type` (D-03).
3. Tighten validation to match the OIDC spec's *optional* semantics (D-04, D-05,
   D-06) and make the discovery doc truthful (D-08, D-09).
4. Opportunistically close parity gaps that break real clients (P-03, P-01,
   P-05, P-02); leave the rest explicitly deferred.

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
| F-27 | **Compliant error codes + statuses.** Token/auth/logout/introspect return RFC 6749 §5.2 codes (`invalid_request`, `invalid_client`→401, `invalid_grant`, `unsupported_grant_type`, `invalid_scope`). | e2e + curl assert lowercase codes and 401 for bad client. |
| F-28 | **`Cache-Control: no-store` + `Pragma: no-cache` on every response containing tokens/credentials** (token, introspect, revoke, userinfo). | Headers present; curl-asserted. |
| F-29 | **Reject `response_type != code`** with `unsupported_response_type` (redirect to validated redirect_uri when possible, else error page). | `response_type=token`/hybrid/`none` rejected. |
| F-30 | **Revocation 401 on failed client auth** (RFC 7009 §2.2). | Bad client → 401 `invalid_client`. |
| F-31 | **Make `nonce`/`state`/`response_mode` optional for the code flow** (nonce still enforced when response_type is implicit/hybrid — which is rejected anyway). | Code flow without nonce/state/response_mode succeeds; defaults apply. |
| F-32 | **`prompt=login` forces re-auth** (session not reused); `prompt=consent` → at least a documented non-goal until the consent screen (F-10) lands. | SSO session + `prompt=login` → login form. |
| F-33 | **Exact `redirect_uri` matching** (drop prefix/trailing-slash normalization; registered URI matched exactly). | Sub-path redirect rejected; exact matches pass. Keep an eye on Keycloak wildcard behavior before flipping. |
| F-34 | **Truthful discovery**: rename `scope_supported`→`scopes_supported`; set `request_parameter_supported`/`request_uri`/mTLS/front-channel/pairwise to false (or implement). | Doc matches implemented surface. |

### P2 — Keycloak parity (opportunistic; subset-by-design acknowledged)

| Ref | Fix | Acceptance |
|-----|-----|-----------|
| F-35 | **`x5t` / `x5t#sha256` as b64url of binary thumbprint** (RFC 7517 §4.7). | JWKS thumbprints verify against cert. |
| F-36 | **Salted `session_state`** (SHA-256 over `client_id origin session_id salt`), iframe computes same value. | Check-session iframe unchanged with Keycloak-style clients; raw session id no longer in URLs. |
| F-37 | **Sliding idle session timeout** — `checkExpiry` idle leg uses `updated_at`. | Session kept alive by activity up to absolute max. |
| F-38 | **`acr` default `1`** for password login (configurable per realm later). | ID token `acr: "1"`. |
| F-39 | **userinfo claims per scope** (`profile` → name/given/family/preferred_username; `email` → email/email_verified) | userinfo honors requested scopes. |
| F-40 | **Drop `nonce` from access/refresh tokens.** | Access/refresh tokens have no `nonce`. |
| P-07…P-09 | **Deferred**: `login_hint`/`max_age`/`ui_locales`; `WWW-Authenticate` on 401; `X-Powered-By` removal — batch with a future hardening pass. | — |

## Non-goals / consciously deferred

- **Implicit & hybrid flows** (`response_type=token`, `id_token`, `code token`,
  etc.) — will *reject* them (F-29) but never implement. Stays `code`-only.
- **`request`/`request_uri` (JAR), mTLS, pairwise subjects, front-channel logout
  execution** — advertised as false after F-34; no implementation planned.
- **Full Keycloak claim/mapper model** (protocol mappers, role/scope mapping,
  resource_access) — see `.scratch/scopes/` workstreams; userinfo scopes
  (F-39) is the only piece pulled in here.
- **Consent screen** — owned by F-10 (`token-lifecycle`/consent); F-32 only
  ensures `prompt=consent` isn't silently *ignored*.
- **Blacklist purge** (P-10) — already tracked as F-19 (`token-lifecycle`).

## Open questions (verify against a real Keycloak)

1. Refresh-token `aud`: this server uses the root issuer; Keycloak appears to
   use the realm URL. Confirm before F-22/F-23 touch the claim set.
2. Introspection `token_type` for ID tokens (`"ID"` here) — confirm Keycloak's
   value before asserting parity in e2e.
3. Whether `redirect_uri` exact-match (F-33) should follow Keycloak's
   `*.path` wildcard semantics instead of plain exact — decide at F-33.

## Acceptance (whole PRD)

1. S-01…S-06 have regression tests (integration + e2e) that fail on the current
   code and pass after.
2. `composer check` green; error-surface assertions added to e2e (`bin/e2e-test.sh`).
3. Discovery doc matches the implemented surface 1:1.
4. No behavioral regression in the happy-path e2e flow.