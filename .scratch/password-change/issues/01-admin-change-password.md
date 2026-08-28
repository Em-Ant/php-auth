# 01 — Admin change-password endpoint

- New admin endpoint to reset/rotate a user's password: `PATCH|POST /admin/users/{id}/password`
  with body `{ "password": "<plaintext>" }`.
- **Server always hashes** the caller-provided plaintext via `SecretsService::hashPassword()`
  (argon2id, same config as create). Never accept a pre-hashed value.
- Add `UserRepository::updatePassword()` (typed, throws `StorageFailed` on PDO error, no
  logger dep — match `UserRepository` conventions).
- Validation: user must exist (404); password non-empty and, if a policy lands (F-11), policy
  compliant; reject no-op (hashing identical plaintext) only if convenient — not required.
- Response: `204` (or `200` with public user shape per repo convention). Never echo plaintext
  or hash.
- **Decide revocation**: does rotating a user's password invalidate their active SSO sessions
  and `offline_sessions`? Rotation is defensive → growing the existing `invalidate` machinery
  is likely correct. Must be decided and tested in this issue, not silently.
- Wire into `public/index.php` admin routes behind `AdminMiddleware` (per AGENTS.md, no admin
  routes in `src/`).
- Tests: unit (`SecretsService` hash path unchanged) + integration (204, 404 on unknown user,
  hash actually stored via `password_verify`, pre-hashed input rejected, revocation behavior).
- Must pass `composer check` (PHPStan 5, PSR12) and the sonar-php self-review.