# CSRF protection on login form

**PRD:** Security Hardening
**Priority:** High

## Problem

`POST /login-actions/authenticate` has no anti-CSRF mechanism. An attacker can forge a cross-site login submission, logging the victim into an attacker-controlled account.

## Solution

Add a CSRF token to the login form. Generate the token during login initialization, store it in the `logins` table alongside the pending login, and validate it on form submission before checking credentials.

## Implementation sketch

- Add a `csrf_token` column to the `logins` table.
- `AuthorizeService::initializeLogin()` generates and stores the token alongside the pending login.
- `login_form.php` renders the token as a hidden field.
- `Authorize::login()` extracts the token from POST body and passes it to `AuthorizeService::ensureValidCredentials()` for validation.
- Mismatch or missing token → return error, do not attempt credential validation.

## Files

`src/services/authorize_service.php`, `src/controllers/authorize.php`, `src/views/login_form.php`, `db/init_v1.sql`
