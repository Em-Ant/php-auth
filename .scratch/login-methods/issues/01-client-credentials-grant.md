# Client Credentials Grant (RFC 6749 §4.4)

status: **DONE** 08/01/2026

Add machine-to-machine token issuance via `grant_type=client_credentials`.

---

## Endpoint

Same `POST /realms/{realm}/protocol/openid-connect/token`.

### Request

| Field      | Required | Description                              |
| ---------- | -------- | ---------------------------------------- |
| `grant_type` | yes    | `client_credentials`                     |
| `client_id`  | yes    | Client name                              |
| `client_secret` | if the client has `require_auth` set | Client secret |
| `scope`      | no      | Space-separated scopes; defaults to realm scope |

### Response

`200 OK` — access token only (no `refresh_token`, no `id_token`):

```json
{
  "access_token": "eyJ...",
  "expires_in": 300,
  "token_type": "Bearer",
  "scope": "openid profile email",
  "not-before-policy": 0
}
```

### Token claims

`typ: Bearer`, `sub`/`azp`/`aud` = client name, `client_id`, `scope`,
`allowed-origins`. No `sid`/`session_state` (no session).

## Changes

### `src/Models/GrantType.php` (new)

Backed string enum: `AuthorizationCode`, `RefreshToken`, `ClientCredentials`.

### `src/Services/InputValidator.php`

`validateTokenParams` now dispatches via `GrantType::tryFrom()` and accepts
`client_credentials`.

### `src/Services/TokenService.php`

Added `createClientCredentialsToken(Realm, Client, string $scope): array`.

### `src/Services/TokenGrantService.php`

- `getTokens` dispatches on `GrantType` and calls new
  `getClientCredentialsTokens()`.
- **Bugfix**: `$client_secret` was read from `$params['code']` instead of
  `$params['client_secret']` — secret validation never ran. Fixed.

### `static/well-known.json`

`grant_types_supported` now includes `client_credentials`.

## Tests

- `InputValidatorTest` — `client_credentials` passes validation.
- `tests/Integration/ClientCredentialsGrantTest.php` (new, 11 tests):
  - well-known advertises the grant
  - access token only (no refresh/id_token), default + explicit scope
  - claims (`sub`/`azp`/`aud` = client, no `sid`)
  - failures: unknown scope, unknown client, unsupported grant type, missing
    client_id, wrong secret (confidential client inserted in setUpBeforeClass)
  - lifecycle: introspect active, revoke → introspect inactive
- `bin/e2e-test.sh` — Step 11 exercises the grant against the live server.

## Verification

- `composer test` — 249 tests pass (was 237)
- `composer stan` — level 5 passes
- `composer cs_check` — PSR12 passes
- `composer test:e2e` — 30/30 pass

## References

- [RFC 6749 §4.4 — Client Credentials Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4)
