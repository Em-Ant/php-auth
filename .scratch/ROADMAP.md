# php-auth — Roadmap

## Foundation (done)

- [x] PSR-4 autoload, file renaming, composer.json cleanup
- [x] Migrate brownie-php → Slim 4 (bootstrap, PSR-7, PSR-15 middleware, views, JSON responses)
- [x] KeyStore interface + FilesystemKeyStore / InMemoryKeyStore
- [x] RedirectUri value object
- [x] LoginStateMachine + LoginEvent / LoginStatus enums
- [x] SessionCookieHandler interface + HttpSessionCookieHandler / InMemorySessionCookieHandler
- [x] PHPUnit setup + unit/integration tests (193 tests)
- [x] Admin auth middleware (Bearer + X-Admin-Key)
- [x] Migration runner + endpoints (migrate, rollback, go, status, dry-run)
- [x] Rate limiting middleware (configurable IP source, per-endpoint limits)
- [x] Health endpoints (`GET /health`, `GET /ready`)
- [x] Database migrations as single schema source (init_v1.sql removed)
- [x] Seed data script (`bin/seed`, dev-only, idempotent)

## Admin API

- [ ] CRUD endpoints: realms, clients, users, key assignment
- [ ] Audit log table + query endpoint
- [ ] Password policy per realm (min length, complexity)

## Login Methods

- [ ] Client Credentials grant (`grant_type=client_credentials`)
- [ ] Resource Owner Password grant (`grant_type=password`)
- [ ] Email magic link (`Mailer` interface + `NativeMailer` adapter)
- [ ] SMTP adapter (future VPS deployment)
- [ ] Social login (generic OAuth2 adapter for Google, GitHub, GitLab)
- [ ] 2FA/TOTP (authenticator app)

## Token Lifecycle

- [x] Token Introspection (`POST /token/introspect`, RFC 7662)
- [x] Token Revocation (`POST /realms/{realm}/protocol/openid-connect/revoke`, RFC 7009)
- [x] Token blacklist table
- [ ] Cleanup job (purge expired blacklist entries)
- [ ] Offline revocation

## Customizable Login Form

- [ ] Per-realm login page config (logo, colors, title, custom CSS)
- [ ] Google-style modal widget (SAM iframe)
- [ ] Fallback full-page form

## Refactor (Wave 2)

- [x] **Container kernel + remove DataSource** ([#07](issues/07-container-kernel.md))
- [x] **Split AuthorizeService** into InputValidator + SessionOrchestrator + AuthenticationOrchestrator

## PHP 8 / PHPStan

- [x] Enums (LoginStatus, LoginEvent)
- [ ] Enums for remaining domain concepts (GrantType, ResponseMode, etc.)
- [ ] Readonly properties, constructor promotion
- [ ] Named arguments, match expressions
- [ ] PHPStan level 5 → 6 → 7 → 8 → 9 (incrementally)
- [ ] PSR12 compliance throughout
