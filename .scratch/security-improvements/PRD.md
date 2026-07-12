# Security Hardening — php-auth

## Problem Statement

The auth server has several security gaps in the HTTP/session layer that compromise user credentials and session integrity:

- The login POST endpoint has no anti-CSRF mechanism, allowing cross-site login forgeries.
- The 3p-cookies endpoint includes a file from a URL parameter without validation.


## Solution

Add CSRF protection to the login form.

## User Stories

1. As a user, I want the login form to be protected against cross-site request forgery, so that an attacker cannot log me into their account or trigger authentication side effects without my knowledge.
2. As an operator, I want the 3p-cookies endpoint to validate its step parameter against a whitelist, so that unexpected values are rejected rather than passed to an include.

## Implementation Decisions

- **CSRF**: The login form will include a hidden token field. The server will validate the token on `POST /login-actions/authenticate`. The token is bound to the login session (the pending `login_id`) — generated during login initialization, stored in the `logins` table, and verified before credential validation.


## Testing Decisions

- CSRF token generation and validation are pure functions — testable without HTTP.

## Out of Scope

- HTTPS/TLS configuration (assumes reverse proxy handles it).
- Rate limiting on login endpoint.
- Account lockout / brute-force protection.
- Session fixation hardening (separate issue).
- Refactoring the view rendering system to avoid `extract()` (architecture concern).


