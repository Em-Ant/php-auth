# Login state machine

**PRD:** Architecture Deepening
**Priority:** Medium

## Problem

Login entity transitions through PENDING → AUTHENTICATED → ACTIVE → EXPIRED. Transitions and per-status TTL checks are split across `AuthorizeService::checkLoginExpiration()` (switch on status) and five `LoginRepository` methods. Understanding the full state diagram requires reading two files.

## Solution

Concentrate transition rules, TTL checks, and persistence into a `LoginStateMachine` module.

## Interface sketch

```php
class LoginStateMachine {
    public function __construct(private ILoginRepo $repo, private Logger $logger);

    /** @throws InvalidInputException if transition not allowed or login expired */
    public function transition(Login $login, string $event): Login;
}
```

Valid event list: `authenticate`, `activate`, `refresh`, `expire`.

## Files

`src/services/authorize_service.php`, `src/repositories/login_repository.php`, `src/interfaces/login_repository.php`, new file in `src/services/`
