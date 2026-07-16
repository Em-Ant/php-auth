# php-auth — Agent guide

## Commands

| Command | Action |
|---|---|
| `composer serve` | Dev server at `localhost:8000` (PHP built-in, `public/` as doc root via `router.php`) |
| `composer stan` | PHPStan level 5 on `src/` and `index.php` |
| `composer cs_check` | PHPCS PSR12 on `src/` and `index.php` |
| `composer cs_fix` | phpcbf auto-fix PSR12 |
| `composer check` | Runs `stan` then `cs_check` — use this before committing |

## First-time setup

1. Create `db/data.db` (empty file, SQLite)
2. `composer setup` — runs migrations then seeds dev data (realms `web`, `test`, users, clients)
3. Generate RSA key pairs in `keys/<kid>/` (call `TokenService::createKeys()` or manually)
4. `composer dump-autoload` after adding new classes (PSR-4, not classmap)

### Migrations

Files in `db/migrations/` are plain SQL: `NNN_name.up.sql` + `NNN_name.down.sql`.
Run via CLI (`composer migrate`) or HTTP (`POST /admin-api/migrations/migrate` with admin Bearer token).

**Seed data (`db/seed.sql`)** is dev-only and never runs in production. Invoke manually via `composer seed` (idempotent — skips if a realm already exists).

## Agent skills

### Issue tracker

This repo uses **local markdown issue tracking** under `.scratch/`. See `.agent/docs/issue-tracker.md`.

Do NOT run `gh` or any other remote issue-tracker CLI — there is no GitHub/GitLab issue tracker configured.

### Domain docs

Single-context. See `.agent/docs/domain.md`.

## Architecture

- **Sole entrypoint**: `index.php` — all routes, DI wiring, and config loading happen here
- **Router**: Slim 4 (PSR-7/PSR-15), replacing `emant/brownie-php`
- **DB**: SQLite via PDO singleton in `src/Repositories/DataSource.php`
- **DI**: Slim's built-in container (PHP-DI or Pimple)
- **Auth flow**: Authorization Code Grant + PKCE + Refresh Token (OIDC-like)
- **No user registration, password reset, or admin API** — pure auth server only
- **Adminer** bundled at `/admin` path

## Design principles
Apply these almost religiously. If a pragmatic violation is needed, consult the user first:
- **SOLID** — Single Responsibility, Open/Closed, Liskov Substitution, Interface Segregation, Dependency Inversion
- **DRY** — don't repeat logic. Extract shared logic into domain services or helper methods.
- **KISS** — simple over clever. Favor flat structures over deep inheritance.
- **Law of Demeter** — talk only to your immediate dependencies. No method chaining across layer boundaries.


## Conventions & quirks

- **`declare(strict_types=1)`** — used consistently across all `src/` files
- **PHP 8 features for NEW code** — enums, readonly properties, constructor promotion, named arguments, match expressions, union types. Do NOT rewrite existing code that isn't being touched; only use new features in new/modified files.
- **Accurate typing** — typed properties, typed params and return types everywhere, avoid `mixed` where possible, use `|null` unions explicitly (no nullable `?type` in new code). This makes PHPStan level bumps mechanical.
- **`$sub_path` global** — set in `index.php` from `config.ini` `base_path`, used in views for URL prefixing behind reverse proxies
- **`AUTH_SESSION` cookie** format: `{realm}\{session_id}` (backslash-separated)
- **`md5` used for `at_hash`** in ID tokens — non-standard but intentional

## Language

Always communicate in English only.
