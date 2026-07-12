# php-auth — Roadmap

## Phase 0 — Foundation (structural changes + architecture modules)

- [x] **PSR-4 autoload + file renaming** — rename dirs to match PSR-4 case (`Services/`, `Models/`, `Repositories/`), rename files to PascalCase, update `composer.json`
- [ ] **Migrate brownie-php → Slim 4** — rewrite `index.php`, replace `Utils::show_view` with PSR-7 Response rendering, replace `Utils::send_json`/`server_error`/etc. with PSR-7 equivalents, wire DI via Slim container. Keep simple PHP `include` views. Inline `get_guid()` as a standalone helper.
- [x] **KeyStore** — interface + `FilesystemKeyStore` / `InMemoryKeyStore`, inject into `TokenService` and `Authorize::sendKeys`
- [x] **RedirectUri** — value object for fragment vs query redirect construction
- [x] **LoginStateMachine** — state transitions (PENDING→AUTHENTICATED→ACTIVE→EXPIRED) + TTL rules in one place, backed by `LoginEvent` and `LoginStatus` enums
- [x] **SessionCookieHandler** — interface + `HttpSessionCookieHandler` / `InMemorySessionCookieHandler`
- [ ] **Database migrations** — migration runner + version table (schema evolution without manual SQL)
- [ ] **Health endpoints** — `GET /health` (server alive), `GET /ready` (DB reachable)
- [ ] **Dockerfile** — one-stage PHP + SQLite + composer, CMD `composer serve`

## Phase 1 — Test Suite (high prio)

- [ ] PHPUnit setup (phpunit.xml, bootstrap)
- [ ] Unit tests: KeyStore, RedirectUri, LoginStateMachine, SessionCookieHandler
- [ ] Integration tests: full authorize→login→token→refresh→logout flow with SQLite in-memory
- [ ] **Rate limiting middleware** — per-IP on `/login-actions/authenticate` and `/token`; configurable per realm

## Phase 2 — Admin API (high prio)

- [ ] Admin auth middleware (API key or bearer token from config)
- [ ] CRUD endpoints: realms, clients, users, key assignment
- [ ] **Audit log table** + query endpoint (who, what, when, success/failure)
- [ ] **Password policy per realm** (min length, complexity) stored in realm config

## Phase 3 — Login Methods (high prio)

- [ ] **Client Credentials grant** (`grant_type=client_credentials`) — service-to-service auth
- [ ] **Resource Owner Password grant** (`grant_type=password`) — for first-party clients
- [ ] **Email magic link** — `Mailer` interface + `NativeMailer` adapter (PHP `mail()`), auto-provisions user with default role
- [ ] **SMTP adapter** (for future VPS deployment, no-op until then)
- [ ] **Social login** — generic OAuth2 adapter for Google, GitHub, GitLab
- [ ] **2FA/TOTP** — authenticator app (optional step in login state machine)

## Phase 4 — Token Lifecycle

- [ ] **Token Introspection** (`POST /token/introspect`, RFC 7662)
- [ ] **Token Revocation** (`POST /token/revoke`, RFC 7009)
- [ ] **Token blacklist table** + cleanup job for expired entries
- [ ] **Offline revocation** — server-side revoke without requiring token to be presented

## Phase 5 — Customizable Login Form (med prio)

- [ ] Per-realm login page config in DB (logo, colors, title, custom CSS)
- [ ] Google-style modal widget (SAM iframe)
- [ ] Fallback full-page form for clients without SAM support

## Phase 6 — PHP 8 + PHPStan 9 (low prio)

- [x] Enums (LoginStatus, LoginEvent)
- [ ] Enums for remaining domain concepts (GrantType, ResponseMode, etc.)
- [ ] Readonly properties, constructor promotion
- [ ] Named arguments, match expressions
- [ ] PHPStan level 5 → 6 → 7 → 8 → 9 (incrementally)
- [ ] PHPCS PSR12 compliance throughout
