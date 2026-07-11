# Consolidate error logging in repositories

**PRD:** Security Hardening
**Priority:** Medium

## Problem

All five repositories call `error_log($e->getMessage())` in their catch blocks instead of the injected application Logger. DB errors vanish silently in production when the SAPI log is off, and the application Logger never sees them.

## Solution

Inject the `Logger` interface into each repository and replace `error_log()` calls with `$this->logger->error()`.

## Implementation sketch

- Add `Logger` parameter to each repository constructor.
- Store as `$this->logger`.
- Replace each `error_log()` call with `$this->logger->error()`.
- Update wiring in `index.php` to pass the logger instance.

## Files

`src/repositories/*.php` (5 files), `src/interfaces/logger.php` (already exists), `index.php`
