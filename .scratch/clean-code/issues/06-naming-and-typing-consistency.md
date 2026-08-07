# Naming and typing consistency

**Severity:** low.

- Untyped getters in `Models/Realm.php`, `Models/Client.php`, `Models/User.php` (`getId()` without `: string`) while `Login`/`Session` are fully typed — contradicts AGENTS.md "accurate typing" convention.
- Mixed snake_case/camelCase locals within the same files (e.g. `$realm_name` vs `$sessionId`).
- `TokenService::createRefreshToken` has an untyped `$realm_name` parameter.
- `Base64Utils::b64UrlDecode` has no return type; `b64UrlEncode` has an untyped parameter.

**Fix:** normalize to camelCase, add return types. Mechanical, do in one batch.
