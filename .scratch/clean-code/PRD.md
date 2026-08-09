# Clean code backlog

Backlog of clean-code smells found during the codebase assessment (session ses_021eec6a8ffeQSzZ7EnP5WCZbp). Not urgent, not business-critical; parked so work survives context loss. Fix in priority order, one batch at a time, verification after each batch (`composer check` + `composer test`).

## Already fixed in this session

- PKCE bug: missing `code_verifier` caused uncaught `TypeError` → 500 (`InputValidator::validateCodeChallenge`)
- Dead admin routes (`/api/admin` stub) removed from `public/index.php` and `TestAppFactory.php`
- `LoginStateMachine` persistence failures now throw `StorageFailed` instead of bare `RuntimeException`
- [Repository error contract](issues/02-repository-error-contract.md): repositories rethrow `StorageFailed` (PDO errors no longer masked as "not found" → 400s); global handler maps them to 500
- `SessionCookieHandler` PSR-7 compliance: reads from `$request->getCookieParams()`, writes `Set-Cookie` header on the response, no more global `setcookie()` / `$_COOKIE`
- [Open redirects](issues/08-open-redirects.md): `prompt=none` error branch + logout now validate the redirect target against the client's registered URI (spec in `.scratch/open-redirects/PRD.md`)

## Issues

1. [Duplicate Slim wiring](issues/01-duplicate-app-wiring.md)
2. [Repository error contract](issues/02-repository-error-contract.md)
3. [AuthenticationOrchestrator god-service](issues/03-auth-orchestrator-god-service.md)
4. [Token validation knowledge duplicated](issues/04-token-validation-duplication.md)
5. [Basic-auth parsing duplicated](issues/05-basic-auth-parsing-duplication.md)
6. [Naming and typing consistency](issues/06-naming-and-typing-consistency.md)
7. [Static InputValidator + dead DI entry](issues/07-static-input-validator.md)
