# Basic-auth parsing duplicated

**Severity:** low — three copies of the same block.

The `Authorization: Basic` → `client_id`/`client_secret` extraction block is copy-pasted in `TokenController`, `IntrospectController`, and `RevokeController`.

**Fix:** extract into `ClientAuthenticator` (or a request helper) and call from all three controllers.
