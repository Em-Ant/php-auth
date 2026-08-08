# Open Redirects — validate redirect URIs in `prompt=none` and logout

**Status:** implemented — done.
**Owner:** agent + user
**Depends on:** nothing (isolated)

## Problem Statement

Two flows redirect the browser to attacker-controlled URLs because the redirect
target is used **before** it is validated against the client's registered URI:

1. **`prompt=none` error branch** — `AuthorizationController::authorize`
   (`src/Controllers/AuthorizationController.php:91-102`). With no valid session
   and `prompt=none`, the response 302s to `$query['redirect_uri']` carrying
   `error=login_required`. The only check that ran is `validateRequiredLoginScope`
   (client exists + scope valid). `redirect_uri` is never matched against the
   client's registered URI because `ensureValidClient` only runs in the
   `initializeLogin` / `createAuthorizedLogin` branches — both *not* taken here.

2. **Logout** — `LogoutController::logout` (`src/Controllers/LogoutController.php:37-45`).
   After validating the `id_token_hint` signature, the response 302s to **any**
   `post_logout_redirect_uri`. No client lookup, no allow-list. OIDC RP-Initiated
   Logout requires validating this value against the client's registered URIs.

For an OAuth/OIDC server these are not ordinary phishing vectors: they bypass the
`validateRedirectUri` allow-list guarantee, enable token leakage in fragment-mode
and same-site redirect scenarios, and are a standard entry point for
credential-phishing against a trusted auth origin.

Related minor defects in the same area:

- `authorize` reads `$query['scope']` / `$query['client_id']` without
  `InputValidator::validateQueryParams`, so malformed queries emit PHP warnings.
- `prompt=none` with an invalid `response_mode` makes `RedirectUri` throw an
  uncaught `InvalidArgumentException` → HTTP 500.

## Goals

1. No redirect to a URI that is not registered for the resolved client, in any
   flow. This is a hard invariant.
2. `prompt=none` behaves per OIDC Core: valid client + valid redirect_uri →
   `error=login_required` redirect; invalid redirect_uri → **no redirect**,
   render the existing `/error` page instead.
3. Logout redirects only to the client's allowed logout targets (identified by
   the `id_token_hint`): the client's registered `redirect_uri` by default
   (subpaths accepted), or per-client `post_logout_redirect_uri` when set.
4. Malformed/missing query params fail with a clean 400 (via
   `InputValidator::validateQueryParams`), not PHP warnings or 500s.

## Non-Goals

- No consent screen, no `prompt=consent` / `prompt=login` semantics.
- No full OIDC RP-Initiated Logout conformance (e.g. `state`, unsigned id_token
  hints, `client_id` fallback, session-management logout). Just close the
  redirect hole.
- No changes to the redirect_uri *matching algorithm* — reuse
  `InputValidator::validateRedirectUri` as-is.
- No separate per-client `post_logout_redirect_uri` config field yet — the
  redirect_uri fallback (with subpaths) is the default validation; the override
  ships when a client config exists. This is spec-compliant: the fallback counts
  as "registered through some other means".

## Behavior spec

### A. `prompt=none` error branch

| Condition | Behavior |
|---|---|
| Valid client, valid `redirect_uri` | 302 with `error=login_required` + `state` (unchanged) |
| Client missing / wrong realm | 400 JSON `invalid client id` (as today, via `validateRequiredLoginScope`) |
| Invalid `redirect_uri` | **302 to `/error` page** (no browser redirect to the bad URI) |
| Missing/invalid required params | 400 JSON (from `validateQueryParams` at top of `authorize`) |
| Invalid `response_mode` | 400 JSON (from `validateQueryParams`) |

### B. Logout

| Condition | Behavior |
|---|---|
| No `id_token_hint` (no session resolvable) | no redirect, response without `Location` |
| Invalid `id_token_hint` | 400 JSON (unchanged) |
| Valid `id_token_hint`, `post_logout_redirect_uri` allowed for that client | redirect (unchanged) |
| Valid `id_token_hint`, `post_logout_redirect_uri` **not** allowed | session still expired, **no redirect** — response without `Location` |
| `post_logout_redirect_uri` present but no `id_token_hint` | no redirect (cannot resolve a client to validate against) |

Client for logout is resolved from the id_token claims: `azp`, falling back to
`aud` when `azp` is absent.

**Allowed logout targets** (a URI is allowed if it is):
- a match (exact or subpath) of the client's registered `redirect_uri` — the
  default, same allow-list rule as authorize; or
- a match (exact or subpath) of the client's dedicated `post_logout_redirect_uri`
  when one is configured (overrides the default).

## Acceptance criteria

- [x] Integration test: `prompt=none`, no session, `redirect_uri` registered →
      302, `Location` contains `error=login_required` + `state`.
- [x] Integration test: `prompt=none`, no session, `redirect_uri` NOT registered
      → **no** `Location` to the bad URI; error page/response instead.
- [x] Integration test: `prompt=none`, valid session → 302 with code (regression).
- [x] Integration test: logout with valid id_token + registered
      `post_logout_redirect_uri` → 302 to it (regression).
- [x] Integration test: logout with valid id_token + subpath of the registered
      `redirect_uri` → 302 to it (subpaths allowed by default).
- [x] Integration test: logout with valid id_token + non-registered
      `post_logout_redirect_uri` → **no** `Location` header.
- [x] Integration test: logout with `post_logout_redirect_uri` but no
      `id_token_hint` → no redirect.
- [x] Integration test: `authorize` with missing `scope` / missing `client_id` →
      400 JSON, no PHP warning surfaced.
- [x] `composer check` clean, full suite green, E2E 36/36.

## Implementation notes

- `AuthenticationOrchestrator::ensureValidClient` is private — expose a public
  validation entry point (e.g. `validateClientRedirect(realm, client_id,
  redirect_uri)`) so `authorize` can validate the `prompt=none` path without a
  full login initialization. Alternatively call `ensureValidClient` directly if
  made public.
- Run `InputValidator::validateQueryParams($query)` at the top of `authorize`
  (it is currently only invoked inside the orchestrator methods).
- For logout, decode the id_token payload (`TokenService::decodeTokenSafely`),
  read `azp`/`aud`, resolve the client, then validate the post-logout target
  via `validateRedirectUri` (default: client's registered `redirect_uri`, so
  subpaths are valid). When validation fails, drop the `Location` header instead
  of building one (logout still proceeds).
- Error-page redirect must not be attacker-influenced — it uses the fixed,
  internal `/error` URL (same pattern as `redirectToError`).

## Testing

Unit + integration (TestAppFactory), no new infrastructure. Follow the existing
`FullFlowTest` conventions; reuse the `web` realm + `playground` client
(registered URI `https://em-ant.gitlab.io/react-playground`) and the `test`
realm + `local` client (`http://localhost:5173`) for negative/positive cases.
