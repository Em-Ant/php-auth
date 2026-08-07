# Open redirects

**Severity:** medium — security.

- `AuthorizationController::authorize` `prompt=none` path redirects to an unvalidated `redirect_uri` (no session means `ensureValidClient` never runs).
- `LogoutController::logout` redirects to any `post_logout_redirect_uri` with no allow-list.

**Fix:** validate both against the client's registered URI before redirecting. Needs a client lookup in the `prompt=none` branch and an allow-list (or registration check) for logout redirects.
