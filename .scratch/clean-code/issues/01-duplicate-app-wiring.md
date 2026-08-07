# Duplicate Slim wiring

**Severity:** medium — every route/middleware change must be made twice and the copies have already drifted.

`public/index.php` and `tests/Support/TestAppFactory.php` duplicate the full route + middleware setup (~200 lines, ~95% identical). Differences already present:

- rate limiting middleware exists only in `public/index.php`
- body-parsing middleware differs (JSON-only vs JSON + form-encoded)
- `TestAppFactory` seeds the DB in-memory

**Fix:** extract shared wiring into a class in `src/` (e.g. `src/App/AppFactory` or a `Router` service) that both the entrypoint and `TestAppFactory` consume. Deferred: large diff, not business-critical.
