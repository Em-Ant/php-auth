# Static InputValidator + dead DI entry

status: **DONE** (2026-08-23) — removed dead `InputValidator::class => \DI\autowire()` entry and unused `use` import from `src/Config/Definitions.php:43,146`. `InputValidator` remains a static facade (`InputValidator::validate*` in `AuthenticationOrchestrator`/`TokenGrantService`/`AuthorizationController`), intentional per `src/Services/InputValidator.php:12` — zero dependencies, pure static methods. No container resolution ever occurred. Verified: `composer test` 458 tests OK, `composer stan` level 5 OK, `composer cs_check` OK, `scan.php` no findings, diff-gate OK.

**Severity:** low.

`InputValidator` is a static facade called as `InputValidator::validate…` from domain services, but it is also autowired in `Definitions.php` (dead entry — never resolved). Static = not mockable; validation logic is coupled into `AuthenticationOrchestrator`/`TokenGrantService`.

**Fix:** either inject it as a regular service, or drop the dead DI entry and keep the static calls if that's the intended style.
