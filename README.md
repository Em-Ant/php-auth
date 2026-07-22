# php auth

OpenID Connect-like PHP auth server implementing the authorization code grant flow.

[![Deploy](https://github.com/Em-Ant/php-auth/actions/workflows/deploy.yml/badge.svg)](https://github.com/Em-Ant/php-auth/actions/workflows/deploy.yml)

## Quick start

```bash
touch db/data.db
composer setup          # migrations + seed data
composer serve          # dev server at localhost:8000
```

Then open the [Keycloak app](https://www.keycloak.org/app/?url=http://localhost:8000&realm=test&client=kc_app)
or any OIDC client pointing to `http://localhost:8000/realms/test`.

## Testing

```bash
composer test           # PHPUnit (218+ tests, unit + integration, in-memory SQLite)
composer test:e2e       # E2E smoke test against real dev server (bash + curl)
composer check          # PHPStan + PHPCS
```

## Dependencies

- PHP 8
- SQLite 3
- OpenSSL
- [BrowniePhP](https://github.com/Em-Ant/brownie-php)

## Architecture

- **Entrypoint**: `public/index.php` loads `config/di.php` (PHP-DI), creates the container, wires Slim.
- **No singleton DB**: Repositories take `\PDO` directly; `DataSource` was removed in Wave 2.
- **Config-driven**: `config.ini` drives issuer, logging, rate limiting, password hashing.
- **Versioned migrations**: plain SQL under `db/migrations/`, run via CLI or admin HTTP endpoint.

## License

MIT
