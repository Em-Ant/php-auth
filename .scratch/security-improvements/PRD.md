# Security Hardening — php-auth

## Problem Statement

The auth server has several security gaps in the HTTP/session layer that compromise user credentials and session integrity:

- The login POST endpoint has no anti-CSRF mechanism, allowing cross-site login forgeries.
- The 3p-cookies endpoint includes a file from a URL parameter without validation.
- DB errors bypass the application logger, vanishing silently in production.
- Input validation is missing on email addresses and the 3p-cookies step parameter.

## Solution

Harden the HTTP boundary: add CSRF protection, validate all user-controlled inputs, and consolidate error reporting so security-relevant failures are visible.

## User Stories

1. As a user, I want the login form to be protected against cross-site request forgery, so that an attacker cannot log me into their account or trigger authentication side effects without my knowledge.
2. As an operator, I want all database errors to be logged through the application logger, so that I can detect storage failures in production monitoring.
3. As a user, I want the server to reject malformed email addresses before attempting authentication, so that invalid requests fail fast.
4. As an operator, I want the 3p-cookies endpoint to validate its step parameter against a whitelist, so that unexpected values are rejected rather than passed to an include.

## Implementation Decisions

- **CSRF**: The login form will include a hidden token field. The server will validate the token on `POST /login-actions/authenticate`. The token is bound to the login session (the pending `login_id`) — generated during login initialization, stored in the `logins` table, and verified before credential validation.
- **3p-cookies step validation**: The `{step}` route parameter will be validated against `['step1.html', 'step2.html']` before inclusion. Invalid values return a 400.
- **Logger consolidation**: Repository catch blocks will receive the application `Logger` via constructor injection instead of calling `error_log()`. This requires adding `Logger` as a constructor parameter to all five repositories.
- **Email validation**: `filter_var($email, FILTER_VALIDATE_EMAIL)` added in `ensureValidCredentials()` before the DB lookup.

## Testing Decisions

- CSRF token generation and validation are pure functions — testable without HTTP.
- Email validation is a one-line filter_var call — covered by existing manual test flow.
- Repository logger injection — verify via PHPStan (constructor parameter compliance). No test suite exists; manual verification via login flow.

## Out of Scope

- HTTPS/TLS configuration (assumes reverse proxy handles it).
- Rate limiting on login endpoint.
- Account lockout / brute-force protection.
- Session fixation hardening (separate issue).
- Refactoring the view rendering system to avoid `extract()` (architecture concern).


