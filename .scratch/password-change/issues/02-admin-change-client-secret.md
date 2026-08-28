# 02 — Admin change-client-secret endpoint

- New admin endpoint to rotate a confidential client's secret:
  `PATCH|POST /admin/clients/{id}/secret` with body `{ "secret": "<plaintext>" }`.
- **Server always hashes** the caller-provided plaintext via `SecretsService::hashPassword()`
  (argon2id, same config as create). Never accept a pre-hashed value.
- Add `ClientRepository::updateSecret()` (typed, throws `StorageFailed` on PDO error, no
  logger dep — match `ClientRepository` conventions).
- **Reject on public clients** (`require_auth = 0`, `client_secret IS NULL`) with 409/422 —
  keeps the "public = no secret" invariant honest. Confirm shape in the issue.
- Response: `204`. Public shape already exposes only `has_secret`
  (`ClientsController::toArray`) — unchanged; never echo plaintext or hash.
- Document: issued JWTs are stateless and unaffected; future `client_credentials` /
  refresh-with-secret calls fail until the caller adopts the new secret.
- Wire into `public/index.php` admin routes behind `AdminMiddleware` (per AGENTS.md, no admin
  routes in `src/`).
- Tests: unit + integration (204, 404 unknown client, 4xx on public client, hash actually
  stored via `password_verify`, old secret no longer verifies).
- Must pass `composer check` (PHPStan 5, PSR12) and the sonar-php self-review.