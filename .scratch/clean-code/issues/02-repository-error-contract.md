# Repository error contract

status: **DONE** — implemented in the assessment session; listed under "Already
fixed" in `.scratch/clean-code/PRD.md`. All repositories rethrow
`StorageFailed` on PDO errors; the global handler maps them to 500.

**Severity:** medium — infrastructure failures are masked as missing data.

Every repository method catches `\PDOException`, logs the message, returns `null` (e.g. `LoginRepository::findById`, `SessionRepository::create`). A DB outage becomes "not found", which callers translate into `ValidationFailed('invalid client id')`-style 400s — wrong status, wrong semantics, and the real error is only in the log.

**Fix:** rethrow a dedicated exception (e.g. `StorageFailed` or a `StorageException`) on genuine failures; return `null` only for empty result sets. Audit callers so the exception maps to 500.

## Comments

**DONE (R-01).** Every repository (`Client`, `User`, `Login`, `Realm`, `Session`, `TokenBlacklist`) now rethrows `StorageFailed` (chaining the original `\PDOException` as `$previous`) instead of logging + returning `null`/`false`; `null`/`false` now mean "empty result set" only. The repositories no longer take a `LoggerInterface` (nothing left to swallow), so observability moved to the boundary: a `StorageFailed` error handler in `public/index.php`/`TestAppFactory` returns a clean `500 {"error":"server_error"}` and logs the chained exception, and `AuthorizationController` logs before redirecting the HTML flow to the error page. The redundant `StorageFailed` catches in `TokenController`/`LogoutController` were removed (the global handler owns that mapping). Covered by `tests/Support/FailingPdo.php` + per-repo failure tests + `tests/Integration/StorageFailureTest.php` (token endpoint now 500, not 400 'invalid code').
