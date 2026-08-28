# 03 — Temp argon2id hash CLI stopgap (optional, dev-only)

- Small CLI script (`bin/hash-password.php`) that takes any plaintext on stdin/arg and
  prints a valid argon2id hash (via the app's own `password_hash` config — reuse the same
  parameters as `SecretsService`).
- Purpose: let an operator hand-write a rotated hash directly into the DB via Adminer or
  `sqlite3` **until** issues #01/#02 ship. Dev/ops convenience only.
- **Must be superseded** by the admin-API endpoints #01/#02 — once they land, this script is
  no longer a supported path and should be removed (dead-code hygiene, php:S1144 spirit).
- No network surface, no secrets logged (input is plaintext by design — run in a trusted
  shell).
- PSR12 + PHPStan clean; `composer check`.