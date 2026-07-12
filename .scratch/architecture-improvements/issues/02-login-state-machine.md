# Login state machine

**Status: Done**

**PRD:** Architecture Deepening
**Priority:** Medium

## Problem

Login entity transitions through PENDING → AUTHENTICATED → ACTIVE → EXPIRED. Transitions and per-status TTL checks are split across `AuthorizeService::checkLoginExpiration()` (switch on status) and five `LoginRepository` methods. Understanding the full state diagram requires reading two files.

## Solution

Concentrate transition rules, TTL checks, and persistence into a `LoginStateMachine` module, backed by `LoginEvent` and `LoginStatus` enums.

## Created files

- `src/Interfaces/LoginStateMachine.php`
- `src/Services/LoginStateMachine.php`
- `src/Models/LoginEvent.php` (enum: Authenticate, Activate, Refresh, Expire, CheckExpiry)
- `src/Models/LoginStatus.php` (enum: Pending, Authenticated, Active, Expired)

## Modified files

- `src/Services/AuthorizeService.php` — inject LoginStateMachine, replace direct repo mutation calls
- `src/Models/Login.php` — `getStatus()` returns `LoginStatus` instead of `string`
- `index.php` — create `LoginStateMachine`, inject into `AuthorizeService`
