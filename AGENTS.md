# php-auth — Agent guide

## Commands

| Command | Action |
|---|---|
| `composer serve` | Dev server at `localhost:8000` (PHP built-in, `index.php` as router) |
| `composer stan` | PHPStan level 5 on `src/` and `index.php` |
| `composer cs_check` | PHPCS PSR12 on `src/` and `index.php` |
| `composer cs_fix` | phpcbf auto-fix PSR12 |
| `composer check` | Runs `stan` then `cs_check` — use this before committing |

## First-time setup

1. Create `db/data.db` (empty file, SQLite)
2. Run `db/init_v1.sql` to create schema
3. Run `db/seed.sql` for seed data (realms `web`, `test`, users, clients)
4. Generate RSA key pairs in `keys/<kid>/` (call `TokenService::createKeys()` or manually)
5. `composer dump-autoload` after adding new classes (classmap, not PSR-4)

## Architecture

- **Sole entrypoint**: `index.php` — all routes, DI wiring, and config loading happen here
- **Router**: `emant/brownie-php` (tiny Express-like custom framework, not Symfony/Laravel)
- **DB**: SQLite via PDO singleton in `src/repositories/data_source.php`
- **Auth flow**: Authorization Code Grant + PKCE + Refresh Token (OIDC-like)
- **No user registration, password reset, or admin API** — pure auth server only
- **Adminer** bundled at `/admin` path

## Conventions & quirks

- **No test suite** — no PHPUnit. Manual testing via `test.http` (VS Code REST Client format)
- **`declare(strict_types=1)`** — used consistently across all `src/` files
- **`$sub_path` global** — set in `index.php` from `config.ini` `base_path`, used in views for URL prefixing behind reverse proxies
- **`AUTH_SESSION` cookie** format: `{realm}\{session_id}` (backslash-separated)
- **`md5` used for `at_hash`** in ID tokens — non-standard but intentional
