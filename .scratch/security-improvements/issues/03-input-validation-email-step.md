# Input validation: email and 3p-cookies step parameter

**PRD:** Security Hardening
**Priority:** Medium

## Problem

Two input validation gaps exist:
1. `$email` in `ensureValidCredentials()` is not validated — `filter_var($email, FILTER_VALIDATE_EMAIL)` is absent.
2. The 3p-cookies `{step}` URL parameter is included in a dynamic `include()` without whitelist validation. While the `3p-` prefix prevents directory escape, the pattern is dangerous.

## Solution

1. Add `filter_var($email, FILTER_VALIDATE_EMAIL)` check in `AuthorizeService::ensureValidCredentials()` before the DB lookup.
2. Whitelist the `step` parameter against `['step1.html', 'step2.html']` before inclusion.

## Files

`src/services/authorize_service.php`, `index.php`
