# Issue #001 — CORS origin allowlist in config.ini

- **Priority:** P2
- **Status:** Open
- **Component:** `src/Middleware/CorsMiddleware.php`

## Problem

`CorsMiddleware` reflects any `Origin` header back with
`Access-Control-Allow-Credentials: true`. An attacker's site could make
credentialed cross-origin requests to this auth server.

## Desired behaviour

Add an `allowed_origins` setting under `[server]` in `config.ini`.

- **`allowed_origins = *`** — echo any origin (current behaviour, dev-friendly).
- **`allowed_origins = https://app.example.com,https://other.com`** — only
  reflect listed origins; unlisted origins get `Access-Control-Allow-Origin: *`
  without credentials.
- **Empty / absent** — fall back to `*` (permissive, for dev).

## Notes

- The wildcard `*` must be supported as a single value meaning "allow all".
- When the origin is not in the allowlist and `*` is not set, the response
  should NOT include `Access-Control-Allow-Credentials: true`.
