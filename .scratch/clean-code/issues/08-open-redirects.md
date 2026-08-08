# Open redirects

**Status:** done — full spec in `.scratch/open-redirects/PRD.md`, implementation issue `.scratch/open-redirects/issues/01-validate-redirect-uris.md`.

- `AuthorizationController::authorize` `prompt=none` path redirects to an unvalidated `redirect_uri` (no session means `ensureValidClient` never runs).
- `LogoutController::logout` redirects to any `post_logout_redirect_uri` with no allow-list.

**Fix:** validate both against the client's registered URI before redirecting. Behavior spec, acceptance criteria, and testing plan in the PRD.
