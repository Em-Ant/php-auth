# AuthenticationOrchestrator god-service

**Severity:** medium — fails the one-sentence test.

`AuthenticationOrchestrator` has 9 dependencies and ~10 responsibilities: login initialization, CSRF validation, authorized-login creation, credential validation, authenticate-login, logout, client-URI lookup, and token parsing/validation. `parseValidToken` is used by `ValidateAccessToken` middleware but lives in an auth service.

**Fix:** move token validation into `TokenService`; consider extracting logout into its own collaborator. Follow-up to the existing split in commit `b308584`.
