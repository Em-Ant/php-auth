# php-auth — Roadmap

## Phase 0 — Foundation (structural changes + architecture modules)

- [x] **PSR-4 autoload + file renaming** — rename dirs to match PSR-4 case (`Services/`, `Models/`, `Repositories/`), rename files to PascalCase, update `composer.json`
- **Migrate brownie-php → Slim 4** — 4 phases tracked in [issue #05](issues/05-slim-migration.md).

  - [x] Phase 1 — Foundation: Slim bootstrap + DI + PSR-7 conversion
  - [x] Phase 2 — Views + JSON rendering (PhpRenderer, JsonResponse)
  - [x] Phase 3 — PSR-15 middleware stack (CORS, RealmProvider, static files, logging, Adminer, 3p/iframe)
  - [x] Phase 4 — Cleanup (get_guid standalone, remove brownie-php)
- [x] **KeyStore** — interface + `FilesystemKeyStore` / `InMemoryKeyStore`, inject into `TokenService` and `Authorize::sendKeys`
- [x] **RedirectUri** — value object for fragment vs query redirect construction
- [x] **LoginStateMachine** — state transitions (PENDING→AUTHENTICATED→ACTIVE→EXPIRED) + TTL rules in one place, backed by `LoginEvent` and `LoginStatus` enums
- [x] **SessionCookieHandler** — interface + `HttpSessionCookieHandler` / `InMemorySessionCookieHandler`

## Phase 1 — Test Suite (high prio)

- [x] PHPUnit setup (phpunit.xml, bootstrap)
- [x] Unit tests: KeyStore, RedirectUri, LoginStateMachine, SessionCookieHandler, repositories, services, middleware
- [x] Integration tests: full authorize→login→token→refresh→logout flow with SQLite in-memory

## Phase 2 — Admin API (high prio)

- [ ] Admin auth middleware (API key or bearer token from config)
- [ ] CRUD endpoints: realms, clients, users, key assignment
- [ ] **Audit log table** + query endpoint (who, what, when, success/failure)
- [ ] **Password policy per realm** (min length, complexity) stored in realm config

## Phase 3 — Production readiness

- [ ] **Rate limiting middleware** — per-IP on `/login-actions/authenticate` and `/token`; configurable per realm
- [ ] **Database migrations** — migration runner + version table (schema evolution without manual SQL)
- [ ] **Health endpoints** — `GET /health` (server alive), `GET /ready` (DB reachable)
- [ ] **Dockerfile** — one-stage PHP + SQLite + composer, CMD `composer serve`

## Phase 4 — Login Methods (high prio)

- [ ] **Client Credentials grant** (`grant_type=client_credentials`) — service-to-service auth
- [ ] **Resource Owner Password grant** (`grant_type=password`) — for first-party clients
- [ ] **Email magic link** — `Mailer` interface + `NativeMailer` adapter (PHP `mail()`), auto-provisions user with default role
- [ ] **SMTP adapter** (for future VPS deployment, no-op until then)
- [ ] **Social login** — generic OAuth2 adapter for Google, GitHub, GitLab
- [ ] **2FA/TOTP** — authenticator app (optional step in login state machine)

## Phase 5 — Token Lifecycle

- [ ] **Token Introspection** (`POST /token/introspect`, RFC 7662)
- [ ] **Token Revocation** (`POST /token/revoke`, RFC 7009)
- [ ] **Token blacklist table** + cleanup job for expired entries
- [ ] **Offline revocation** — server-side revoke without requiring token to be presented

## Phase 6 — Customizable Login Form (med prio)

- [ ] Per-realm login page config in DB (logo, colors, title, custom CSS)
- [ ] Google-style modal widget (SAM iframe)
- [ ] Fallback full-page form for clients without SAM support

## Phase 7 — PHP 8 + PHPStan 9 (10 and upgrade phpstan ?) (low prio)

- [x] Enums (LoginStatus, LoginEvent)
- [ ] Enums for remaining domain concepts (GrantType, ResponseMode, etc.)
- [ ] Readonly properties, constructor promotion
- [ ] Named arguments, match expressions
- [ ] PHPStan level 5 → 6 → 7 → 8 → 9 (incrementally)
- [ ] PHPCS PSR12 compliance throughout
