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
| F-27 | **Compliant error codes + statuses.** Token/auth/logout/introspect return RFC 6749 §5.2 codes (`invalid_request`, `invalid_client`→401, `invalid_grant`, `unsupported_grant_type`, `invalid_scope`). | e2e + curl assert lowercase codes and 401 for bad client. |
| F-28 | **`Cache-Control: no-store` + `Pragma: no-cache` on every response containing tokens/credentials** (token, introspect, revoke, userinfo). | Headers present; curl-asserted. |
| F-29 | **Reject `response_type != code`** with `unsupported_response_type` (redirect to validated redirect_uri when possible, else error page). | `response_type=token`/hybrid/`none` rejected. |
| F-30 | **Revocation 401 on failed client auth** (RFC 7009 §2.2). | Bad client → 401 `invalid_client`. |
| F-31 | **Make `nonce`/`state`/`response_mode` optional for the code flow** (nonce still enforced when response_type is implicit/hybrid — which is rejected anyway). | Code flow without nonce/state/response_mode succeeds; defaults apply. |
| F-32 | **`prompt=login` forces re-auth** (session not reused); `prompt=consent` → at least a documented non-goal until the consent screen (F-10) lands. | SSO session + `prompt=login` → login form. |
| F-33 | **Exact `redirect_uri` matching** (drop prefix/trailing-slash normalization; registered URI matched exactly). ✅ verified live — Keycloak uses exact match, no implicit prefix/sub-path/query; wildcards only when explicitly registered. | Sub-path redirect rejected; exact matches pass. |
| F-34 | **Truthful discovery**: rename `scope_supported`→`scopes_supported`; set `request_parameter_supported`/`request_uri`/mTLS/front-channel/pairwise to false (or implement). | Doc matches implemented surface. |

### P2 — Keycloak parity (opportunistic; subset-by-design acknowledged)

| Ref | Fix | Acceptance |
|-----|-----|-----------|
| F-35 | **`x5t` / `x5t#sha256` as b64url of binary thumbprint** (RFC 7517 §4.7). ✅ verified live — Keycloak emits b64url of SHA-1/SHA-256 over the DER cert; both matched recomputation. | JWKS thumbprints verify against cert. |
| F-36 | **`session_state` — corrected premise (verified live).** Keycloak sends the **raw session-id UUID** in the auth response / ID token, *not* a salted hash. The salted value lives only in the `KEYCLOAK_SESSION` cookie, and the check-session iframe computes `SHA-256(session_state)` client-side and compares it to that cookie (verified: cookie = b64url(SHA-256(session_state))). Our raw-session-id `session_state` is close to correct; the actual gap is the iframe/cookie mechanism, not the claim value. | Check-session iframe interoperates with Keycloak-style clients; raw session id not in URLs (moved to cookie). |
| F-37 | **Sliding idle session timeout** — `checkExpiry` idle leg uses `updated_at`. | Session kept alive by activity up to absolute max. |
| F-38 | **`acr` default `1`** for password login (configurable per realm later). ✅ verified live — Keycloak reports `1` for password auth. | ID token `acr: "1"`. |
| F-39 | **userinfo claims per scope** (`profile` → name/given/family/preferred_username; `email` → email/email_verified) | userinfo honors requested scopes. |
| F-40 | **Drop `nonce` from access/refresh tokens.** | Access/refresh tokens have no `nonce`. |
| P-07…P-09 | **Deferred**: `login_hint`/`max_age`/`ui_locales`; `WWW-Authenticate` on 401; `X-Powered-By` removal — batch with a future hardening pass. | — |

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

## Open questions — verified against a live Keycloak (2026-08-19)

All six probes run against a running Keycloak (realm + confidential/public
clients + password-grant and code-flow tokens, then removed after probing).

1. **Refresh-token `aud`** — ✅ verified: Keycloak uses the **realm URL**
   (`http://localhost:8080/realms/<realm>`), NOT the root issuer. Our server
   uses the root issuer → **real mismatch; fix the claim set when F-22/F-23
   touch it.** (Also observed: AT `aud` = `account`, RT `azp` = client id.)
2. **Introspection `token_type` for ID tokens** — ✅ verified: Keycloak returns
   `"ID"` with `typ: ID`, `active: true`. Our `"ID"` is **correct parity**; safe
   to assert in e2e.
3. **`redirect_uri` matching (F-33)** — ✅ verified: Keycloak does **exact
   match** with no implicit prefix/sub-path/query normalization (all → `400
   Invalid parameter: redirect_uri`). Wildcards (`*`) only match when
   *explicitly registered* per path (`https://app.example.com/other/*`), match
   any depth, allow query strings, and match zero-length after the slash; a
   sibling path (`/otherx`) is rejected. → Keep F-33 as exact match; wildcard
   support is optional and only for explicitly-registered patterns.
4. **`session_state` (F-36)** — ✅ verified (premise corrected): see F-36 row
   above. `session_state` is a raw session-id UUID; the salted SHA-256 is the
   `KEYCLOAK_SESSION` cookie, recomputed by the iframe.
5. **`x5t` / `x5t#S256` (F-35)** — ✅ verified: b64url of binary thumbprint
   (SHA-1 / SHA-256 over DER cert); both matched recomputation.
6. **`acr` (F-38)** — ✅ verified: `"1"` for password auth.

**Runtime note:** probe instance left running (`localhost:8080`, Quarkus, no
docker). Dev server uses port 8000, no clash. Can be stopped any time — the
verified answers above are persisted here.

## Acceptance (whole PRD)

1. S-01…S-06 have regression tests (integration + e2e) that fail on the current
   code and pass after.
2. `composer check` green; error-surface assertions added to e2e (`bin/e2e-test.sh`).
3. Discovery doc matches the implemented surface 1:1.
4. No behavioral regression in the happy-path e2e flow.
5. Refresh-token `aud` claim set updated to the realm URL (verified parity, Q1).
