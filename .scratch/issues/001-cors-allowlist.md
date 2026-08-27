# Issue #001 — CORS origin allowlist in config.ini

- **Priority:** P2
- **Status:** Closed (2026-08-27)
- **Component:** `src/Middleware/CorsMiddleware.php`

## Resolution

Implemented as specified:

- `allowed_origins` setting under `[server]` in `config.ini` (commented example
  added; absent/empty → allow-all for dev compatibility).
- Parsed once in `Definitions::get()` into a `list<string>`
  (`parseAllowedOrigins()`), injected through the DI entry `allowed_origins`
  and wired in `AppBuilder` — no config parsing inside the middleware.
- Allowlisted origin: reflected with `Access-Control-Allow-Credentials: true`.
- Unlisted origin: `Access-Control-Allow-Origin: *`, no credentials header
  (both on preflight and simple requests).
- `*` or empty list preserves the previous reflect-any-origin behaviour.
- Unit tests extended in `tests/Unit/Middleware/CorsMiddlewareTest.php`
  (allowlist echo, unlisted → wildcard without credentials, unlisted
  preflight, empty-list fallback).

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
