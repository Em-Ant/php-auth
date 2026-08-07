# Static InputValidator + dead DI entry

**Severity:** low.

`InputValidator` is a static facade called as `InputValidator::validate…` from domain services, but it is also autowired in `Definitions.php` (dead entry — never resolved). Static = not mockable; validation logic is coupled into `AuthenticationOrchestrator`/`TokenGrantService`.

**Fix:** either inject it as a regular service, or drop the dead DI entry and keep the static calls if that's the intended style.
