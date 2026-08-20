# Keycloak Parity — opportunistic fix plan

**Status:** open — opportunistic. This server is by design a *functional subset*
of Keycloak, not a clone, so parity gaps are ranked below OIDC spec compliance.
Key behaviors verified live against a real Keycloak on 2026-08-19 (see "Open
questions").
**Owner:** agent + user
**Depends on:** nothing; F-41 intersects the `scopes/` workstream (userinfo
claims per scope)

> **Renumbering note:** this PRD was split out of the former mixed
> `.scratch/oidc-compliance/PRD.md` (which is now OIDC-compliance only). The
> old P2 series used F-35…F-40, which collided with BACKLOG F-35/F-36
> (clean-code fixes). Parity fixes are renumbered F-37…F-43 here.

## Problem Statement

Audited against a real Keycloak, the server differs in a set of small ways that
were **by design** — but a few break real Keycloak clients or leak secrets and
are worth closing opportunistically.

## The model — stance on Keycloak parity

- **Functional subset, not a clone.** Keycloak parity was a *design decision*,
  not a debt item: this server implements the subset of Keycloak's OIDC surface
  that the product needs (auth-code + client-credentials, refresh/introspect/
  revoke/logout, PKCE-S256, check-session iframe). Parity items are
  **opportunistic** — do them when they intersect feature work, don't block on
  them.
- **The only parity items that matter now** are the ones that *break real
  Keycloak clients* or *leak secrets*: `x5t` (breaks JWKS thumbprint
  verification), `session_state` format (breaks check-session iframe against
  clients that compute the salted hash), sliding idle timeout (breaks SSO
  lifetime expectations).
- **Spec compliance is mandatory.** RFC 6749 / OIDC Core *MUST*s are not
  negotiable and outrank every parity item. See `.scratch/oidc-compliance/PRD.md`.

## Current State (verified)

Every row below was reproduced over HTTP against a running dev server
(`php -S` + `router.php`) unless noted `(code)`.

| # | Finding | Severity | Where |
|---|---------|----------|-------|
| P-01 | `session_state` = raw session id (Keycloak: salted SHA-256) | Low | `AuthorizationController`, `TokenService` |
| P-02 | `acr` hardcoded `"0"` (Keycloak reports `1` for password auth) | Low | `SessionOrchestrator::create`, schema default |
| P-03 | JWKS `x5t` / `x5t#sha256` = b64url of the *hex* fingerprint (RFC 7517 §4.7 requires b64url of binary thumbprint) | Med | `TokenService::createKeys` |
| P-04 | `nonce` embedded in access & refresh tokens (Keycloak: ID token only) | Low | `TokenService` |
| P-05 | Idle session timeout never slides — measured from `created_at`, ignores `updated_at` | Med | `SessionOrchestrator::checkExpiry` |
| P-06 | userinfo returns only `sub` + `preferred_username` regardless of scope; `claims_supported` advertises more | Low | `OidcController::sendUserInfo` |
| P-07 | Optional auth-request params ignored: `login_hint`, `max_age`, `acr_values`, `ui_locales`, `display`, `claims` | Low | `AuthorizationController` |
| P-08 | userinfo missing-token → 400; no `WWW-Authenticate` on 401s | Low | `ValidateAccessToken` |
| P-09 | `X-Powered-By: PHP/8.3.6` leaked | Low | Slim/PHP default |
| P-10 | Token blacklist never purged (unbounded growth) | Low | `TokenBlacklistRepository` — already tracked as F-19 (`token-lifecycle`) |

## Prioritized fixes

### P2 — Keycloak parity (opportunistic; subset-by-design acknowledged)

| Ref | Fix | Acceptance |
|-----|-----|-----------|
| F-37 | **`x5t` / `x5t#sha256` as b64url of binary thumbprint** (RFC 7517 §4.7). ✅ verified live — Keycloak emits b64url of SHA-1/SHA-256 over the DER cert; both matched recomputation. | JWKS thumbprints verify against cert. |
| F-38 | **`session_state` — corrected premise (verified live).** Keycloak sends the **raw session-id UUID** in the auth response / ID token, *not* a salted hash. The salted value lives only in the `KEYCLOAK_SESSION` cookie, and the check-session iframe computes `SHA-256(session_state)` client-side and compares it to that cookie (verified: cookie = b64url(SHA-256(session_state))). Our raw-session-id `session_state` is close to correct; the actual gap is the iframe/cookie mechanism, not the claim value. | Check-session iframe interoperates with Keycloak-style clients; raw session id not in URLs (moved to cookie). |
| F-39 | **Sliding idle session timeout** — `checkExpiry` idle leg uses `updated_at`. | Session kept alive by activity up to absolute max. |
| F-40 | **`acr` default `1`** for password login (configurable per realm later). ✅ verified live — Keycloak reports `1` for password auth. | ID token `acr: "1"`. |
| F-41 | **userinfo claims per scope** (`profile` → name/given/family/preferred_username; `email` → email/email_verified) | userinfo honors requested scopes. |
| F-42 | **Drop `nonce` from access/refresh tokens.** | Access/refresh tokens have no `nonce`. |

### P3 — Deferred

| Ref | Fix | Acceptance |
|-----|-----|-----------|
| F-43 | **Batch**: `login_hint`/`max_age`/`ui_locales` (P-07); `WWW-Authenticate` on 401 (P-08); `X-Powered-By` removal (P-09) — with a future hardening pass. | — |

## Non-goals / consciously deferred

- **Full Keycloak claim/mapper model** (protocol mappers, role/scope mapping,
  resource_access) — see `.scratch/scopes/` workstreams; userinfo scopes
  (F-41) is the only piece pulled in here.
- **Refresh-token `aud` claim set** — verified mismatch (Q1 below): Keycloak
  uses the realm URL; ours uses the root issuer. Fix opportunistically the next
  time token issuance is touched.
- **Blacklist purge** (P-10) — already tracked as F-19 (`token-lifecycle`).

## Open questions — verified against a live Keycloak (2026-08-19)

All six probes run against a running Keycloak (realm + confidential/public
clients + password-grant and code-flow tokens, then removed after probing).

1. **Refresh-token `aud`** — ✅ verified: Keycloak uses the **realm URL**
   (`http://localhost:8080/realms/<realm>`), NOT the root issuer. Our server
   uses the root issuer → **real mismatch; fix the claim set the next time
   token issuance is touched.** (Also observed: AT `aud` = `account`, RT `azp`
   = client id.)
2. **Introspection `token_type` for ID tokens** — ✅ verified: Keycloak returns
   `"ID"` with `typ: ID`, `active: true`. Our `"ID"` is **correct parity**; safe
   to assert in e2e.
3. **`redirect_uri` matching** — ✅ verified: Keycloak does **exact match** with
   no implicit prefix/sub-path/query normalization (all → `400 Invalid
   parameter: redirect_uri`). Wildcards (`*`) only match when *explicitly
   registered* per path (`https://app.example.com/other/*`), match any depth,
   allow query strings, and match zero-length after the slash; a sibling path
   (`/otherx`) is rejected. → Ours already matches exactly (OIDC F-33);
   wildcard support is optional and only for explicitly-registered patterns.
   ✅ **F-44 implemented** (2026-08-20): trailing-`*` opt-in with strict
   origin binding (no cross-origin bleed, mirrors the 26.6.3 hostname fix);
   seed migrated to wildcard form; see `oidc-compliance/PRD.md` note.
4. **`session_state` (F-38)** — ✅ verified (premise corrected): see F-38 row
   above. `session_state` is a raw session-id UUID; the salted SHA-256 is the
   `KEYCLOAK_SESSION` cookie, recomputed by the iframe.
5. **`x5t` / `x5t#S256` (F-37)** — ✅ verified: b64url of binary thumbprint
   (SHA-1 / SHA-256 over DER cert); both matched recomputation.
6. **`acr` (F-40)** — ✅ verified: `"1"` for password auth.

**Runtime note:** probe instance left running (`localhost:8080`, Quarkus, no
docker). Dev server uses port 8000, no clash. Can be stopped any time — the
verified answers above are persisted here.

## Acceptance

1. `x5t` / `x5t#sha256` verify against the cert (F-37).
2. Check-session iframe interoperates with a Keycloak-style client (F-38).
3. Idle session timeout slides with `updated_at` (F-39).
4. `acr: "1"` for password login (F-40).
5. userinfo honors requested scopes (F-41).
6. Refresh-token `aud` uses the realm URL (verified parity, Q1).