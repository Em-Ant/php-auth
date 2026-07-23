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

**Seed data (`db/seed.sql`)** is dev-only and never runs in production. Invoke manually via `composer seed` (idempotent — skips if a realm already exists).

## Agent skills

### Issue tracker

This repo uses **local markdown issue tracking** under `.scratch/`. See `.agent/docs/issue-tracker.md`.

Do NOT run `gh` or any other remote issue-tracker CLI — there is no GitHub/GitLab issue tracker configured.

### Domain docs

Single-context. See `.agent/docs/domain.md`.

## Architecture

### Entrypoint

`public/index.php` is the single entrypoint. It loads `config/di.php` (PHP-DI definitions), creates the container, and wires Slim with all routes and middleware live — no separate route files.

### DI container

`config/di.php` defines every service, repository, controller, and middleware as PHP-DI entries. Autowiring is used wherever possible. Key bindings:

| Interface | Implementation |
|---|---|
| `\PDO` | Shared factory (SQLite via `db/data.db`) |
| `Psr\Log\LoggerInterface` | Monolog (stdout + file) |
| `KeyStore` | `FilesystemKeyStore` |
| `SessionCookieHandler` | `HttpSessionCookieHandler` |
| `ClientRepository` / `SessionRepository` / `LoginRepository` / `UserRepository` / `RealmRepository` | Repositories take `\PDO` + `LoggerInterface` |

Config parameters (`issuer`, `base_path`, `password_hashing`, `rate_limiting`, etc.) are parsed from `config.ini` at definition time and injected via `\DI\get()`.

### Testing

- **Integration tests** (`tests/Integration/`) bootstrap via `TestAppFactory::createApp()`, which loads `config/di.php`, overrides `\PDO` with in-memory SQLite, runs migrations + seed, and returns a fully wired Slim app.
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
- **`$sub_path` global** — set in `config/di.php` from `config.ini` `base_path`, used in views for URL prefixing behind reverse proxies
- **`AUTH_SESSION` cookie** format: `{realm}\{session_id}` (backslash-separated)
- **`md5` used for `at_hash`** in ID tokens — non-standard but intentional
- no nested ternaries
- avoid nested if blocks if possible, use early returns instead. Mandatory to avoid 3 levels of nested conditional blocks

## Language

Always communicate in English only.
