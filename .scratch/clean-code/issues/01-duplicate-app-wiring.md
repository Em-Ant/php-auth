# Duplicate Slim wiring

status: **DONE** 2026-08-25 (R-07)

**Severity:** medium — every route/middleware change must be made twice and the copies have already drifted.

`public/index.php` and `tests/Support/TestAppFactory.php` duplicate the full route + middleware setup (~200 lines, ~95% identical). Differences already present:

- rate limiting middleware exists only in `public/index.php`
- body-parsing middleware differs (JSON-only vs JSON + form-encoded)
- `TestAppFactory` seeds the DB in-memory

**Fix:** extract shared wiring into a class in `src/` (e.g. `src/App/AppFactory` or a `Router` service) that both the entrypoint and `TestAppFactory` consume. Deferred: large diff, not business-critical.

## Comments

### 2026-08-25 — done

Extracted `src/App/AppBuilder::create($container, rateLimiting: bool)` —
error handlers, body parsing, CORS/request logging, and all route groups
(OIDC incl. iframe/3p pages, admin CRUD, migrations, adminer, health) live in
one place now. `public/index.php` shrank to ~20 lines; `TestAppFactory` to
container overrides + migrate/seed + one builder call.

Environment differences kept explicit:
- rate limiting: production passes `rateLimiting: true`; tests default off
  (`RateLimitingTest` keeps its own focused app).
- body parsing unified to the superset (JSON with charset suffix +
  form-encoded) — prod gains charset-tolerant JSON and form-encoded parsing,
  a deliberate harmonization validated by e2e.

The drift this issue predicted did happen (R-03: `ValidateAccessToken`
rewired in tests but forgotten in prod until e2e caught it), which is why
this got pulled ahead of A-03.

Verified: phpstan 0 errors, PHPCS clean, PHPUnit 493/493, E2E 171/171,
sonar diff gate ok. Row removed from BACKLOG queue — **clean-code PRD
#01–#11 all closed.**
