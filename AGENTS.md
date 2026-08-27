# php-auth — Agent guide

## Commands

| Command | Action |
|---|---|
| `composer serve` | Dev server at `localhost:8000` (PHP built-in, `public/` as doc root via `router.php`) |
| `composer test` | PHPUnit (unit + integration) |
| `composer test:e2e` | E2E smoke test against real dev server (bash + curl, no browser) |
| `composer stan` | PHPStan level 5 on `src/` and `public/index.php` |
| `composer cs_check` | PHPCS PSR12 on `src/` and `public/index.php` |
| `composer cs_fix` | phpcbf auto-fix PSR12 |
| `composer check` | Runs `stan` then `cs_check` — use this before committing |

## First-time setup

1. Create `db/data.db` (empty file, SQLite)
2. `composer setup` — runs migrations then seeds dev data (realms `web`, `test`, users, clients)
3. Generate RSA key pairs in `keys/<kid>/` (call `TokenService::createKeys()` or manually)
4. `composer dump-autoload` after adding new classes (PSR-4, not classmap)

### Migrations

Files in `migrations/` are plain SQL: `NNN_name.up.sql` + `NNN_name.down.sql`.
Run via CLI (`composer migrate`) or HTTP (`POST /db/migrations/migrate` with admin Bearer token).

**SQLite floor: 3.31** (prod shared hosting, older bundled SQLite). Avoid newer constructs — notably `ALTER TABLE ... DROP COLUMN`; prefer retain-and-abandon for dead columns. If a migration is destructive/incompatible anyway, it is *risky* and needs a release plan with precomputed manual remediation SQL — see `docs/adr/0002`.

**Sonar: never write an `UPDATE` (or `DELETE`) without a `WHERE` clause** — in migrations, `db/seed.sql`, or any SQL. An unguarded `UPDATE` fails Sonar's quality gate and blocks the release. For deliberate full-table transforms, write an explicit guarded condition that preserves the semantics (e.g. a NULL-safe backfill: `UPDATE users SET email_verified = 1 WHERE email_verified IS NOT 1;`).

**Seed data (`db/seed.sql`)** is dev-only and never runs in production. Invoke manually via `composer seed` (idempotent — skips if a realm already exists).

## Agent skills

### Issue tracker

This repo uses **local markdown issue tracking** under `.scratch/`. See `.agent/docs/issue-tracker.md`.

Do NOT run `gh` or any other remote issue-tracker CLI — there is no GitHub/GitLab issue tracker configured.

### Domain docs

Single-context. See `.agent/docs/domain.md`.

### Clean code & Sonar Cloud

- **Always apply the `clean-code` skill** when writing, editing, reviewing, or refactoring code.
- **Code must be compliant with the PHP "Sonar way" ruleset** used by SonarCloud. **Always apply the `sonar-php` skill** (self-review against rule keys + heuristic scan) for any PHP code you write or modify, before reporting the work done.
- No analyzer runs in CI here; compliance is enforced by the agent applying the `sonar-php` self-review discipline and reporting rule-keyed findings.

## Architecture

### Entrypoint

`public/index.php` is the single entrypoint. It loads the PHP-DI definitions via `Definitions::get()`, creates the container, and wires Slim with all routes and middleware live — no separate route files.

### DI container

`src/Config/Definitions.php` (`Definitions::get()`) defines every service, repository, controller, and middleware as PHP-DI entries. Autowiring is used wherever possible. Key bindings:

| Interface | Implementation |
|---|---|
| `\PDO` | Shared factory (SQLite via `db/data.db`) |
| `Psr\Log\LoggerInterface` | Monolog (stdout + file) |
| `KeyStore` | `FilesystemKeyStore` |
| `SessionCookieHandler` | `HttpSessionCookieHandler` |
| `ClientRepository` / `SessionRepository` / `LoginRepository` / `UserRepository` / `RealmRepository` | Repositories take `\PDO` and rethrow `StorageFailed` on PDO errors (no logger dependency) |

Config parameters (`issuer`, `base_path`, `password_hashing`, `rate_limiting`, etc.) are parsed from `config.ini` at definition time and injected via `\DI\get()`.

### Testing

- **Integration tests** (`tests/Integration/`) bootstrap via `TestAppFactory::createApp()`, which gets the definitions from `Definitions::get()`, overrides `\PDO` with in-memory SQLite, runs migrations + seed, and returns a fully wired Slim app.
- **Repository tests** extend `RepositoryTestCase` which provides an in-memory SQLite with migrations + seed applied.
- **E2E test** (`bin/e2e-test.sh`) starts the PHP dev server, runs the full OIDC flow via curl (auth → login → token → refresh), and verifies every step.

Key agent-steering choices:

- **No admin API routes in `src/`** — admin endpoints belong in `public/index.php` alongside public routes
- **Test against in-memory SQLite** using `MigrationRunner`, never raw SQL files
- **Rate limiting IP source** must come from config (`remote_addr` or `x_forwarded_for`), never hardcoded

## Design principles
Apply these almost religiously. If a pragmatic violation is needed, consult the user first:
- **SOLID** — Single Responsibility, Open/Closed, Liskov Substitution, Interface Segregation, Dependency Inversion
- **DRY** — don't repeat logic. Extract shared logic into domain services or helper methods.
- **KISS** — simple over clever. Favor flat structures over deep inheritance.
- **Law of Demeter** — talk only to your immediate dependencies. No method chaining across layer boundaries.


## Conventions

- **`declare(strict_types=1)`** — used consistently across all `src/` files
- **PHP 8 features for NEW code** — enums, readonly properties, constructor promotion, named arguments, match expressions, union types. Do NOT rewrite existing code that isn't being touched; only use new features in new/modified files.
- **Accurate typing** — typed properties, typed params and return types everywhere, avoid `mixed` where possible, use `|null` unions explicitly (no nullable `?type` in new code). This makes PHPStan level bumps mechanical.
- **`$sub_path` global** — set in `Definitions::get()` from `config.ini` `base_path`, used in views for URL prefixing behind reverse proxies
- **`AUTH_SESSION` cookie** format: `{realm}\{session_id}` (backslash-separated)
- **`at_hash`** in ID tokens is OIDC-compliant: left-most half of SHA-256 over the access token, base64url-encoded (see `TokenService::calculateAtHash()`)
- no nested ternaries
- avoid nested if blocks if possible, use early returns instead. Mandatory to avoid 3 levels of nested conditional blocks

## Language

Always communicate in English only.
