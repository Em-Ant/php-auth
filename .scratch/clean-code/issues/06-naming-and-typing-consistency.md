# Naming and typing consistency

**Severity:** low.

- Untyped getters in `Models/Realm.php`, `Models/Client.php`, `Models/User.php` (`getId()` without `: string`) while `Login`/`Session` are fully typed — contradicts AGENTS.md "accurate typing" convention.
- Mixed snake_case/camelCase locals within the same files (e.g. `$realm_name` vs `$sessionId`).
- `TokenService::createRefreshToken` has an untyped `$realm_name` parameter.
- `Base64Utils::b64UrlDecode` has no return type; `b64UrlEncode` has an untyped parameter.

**Fix:** normalize to camelCase, add return types. Mechanical, do in one batch.

## Comments

### 2026-08-25 — done

- **Return types:** added to `Realm::getId/getName/getKeysId`,
  `Client::getId/getName/getRealmId/getUri/getClientSecret`, and
  `Base64Utils::b64UrlEncode/b64UrlDecode`. `User.php` was already fully
  typed — that item was stale.
- **Naming:** all snake_case locals/params/private props normalized to
  camelCase across services, controllers, middleware (12 files,
  ~250 lines). String keys, SQL params, view vars, `$sub_path`, and
  interface signatures untouched.
- **Deliberately out of scope:** Model private properties + constructor
  params (they mirror DB columns; renaming breaks every named-arg call
  site incl. tests), repositories (SQL-layer naming, R-12 territory),
  views.
- One wiring fix required: `Definitions.php`
  `constructorParameter('mountPath', …)` follows the rename.
- Verified: phpstan clean, PHPCS clean, PHPUnit 493/493 green,
  E2E smoke 171/171, sonar scan diff-gate ok (remaining MINOR findings are
  pre-existing duplication blocks, tracked under other issues). Row removed
  from BACKLOG queue.
