# Phase 1 — Derive well-known `scope_supported` from realm scopes

status: **DONE** (first step of `.scratch/scopes/PRD.md`)

## Problem

`static/well-known.json` hardcodes `scope_supported`:

```json
"scope_supported": ["openid", "profile", "user", "admin", "read", "write", "acr"]
```

This advertises scopes a realm may not even recognize, and a realm's actual
scope config is invisible to clients. Real OAuth servers (Keycloak included)
advertise the scopes they actually know.

## Change

Make `scope_supported` per-realm, derived from `realms.scope` plus `openid`.

- `OidcController::sendConfig` currently does a `str_replace('<<ISSUER>>', ...)`
  on the static template. Add a second placeholder, e.g. `<<SCOPE_SUPPORTED>>`,
  replaced with the JSON array:
  `array_values(array_unique(array_merge(['openid'], $realm->getScope())))`.
- `openid` is always advertised because the auth-code flow requires it
  (`InputValidator::validateQueryParams`).

## Touch points

- `static/well-known.json` — placeholder in the `scope_supported` array.
- `src/Controllers/OidcController.php` — replace the placeholder.
- Test: extend an existing integration test (e.g. `MiscEndpointsTest`) to assert
  `scope_supported` equals the realm's scopes + `openid`, and that it no longer
  contains the old hardcoded `acr`/`write` values.

## Acceptance

- `GET /realms/test/.well-known/openid-configuration` → `scope_supported`
  contains `openid` and exactly the test realm's configured scopes.
- All existing tests + `composer check` stay green.
