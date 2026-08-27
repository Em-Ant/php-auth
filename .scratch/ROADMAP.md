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

- [x] CRUD endpoints: realms, clients, users, key assignment
- [x] Session/login management: list/delete sessions & logins, invalidate-by-user/client, user deactivation (`valid=FALSE`) — the SSO part of offline revocation
- [ ] Audit log table + query endpoint
- [ ] Password policy per realm (min length, complexity)
- [ ] Retire the `realm_roles` string field on user create/update (ADR-0001 D4 shim) — breaking admin-API change, roles become explicit entities assigned via `POST /admin/users/{id}/roles`
- [x] Offline revocation: revoke a user's `offline_sessions` (SSO session/login revoke already shipped) — [token-lifecycle #04](token-lifecycle/issues/04-offline-revocation.md) (done 2026-08-23, F-06)
- [ ] Maintenance task: blacklist purge + expired-session cleanup (admin-triggered; manual / deploy-time / CI-scheduled) — see [token-lifecycle #05](token-lifecycle/issues/05-cleanup-job.md)

## Admin Auth & Tools

Admin API auth evolution for a separate Admin UI (React+Vite+shadcn, different repo) and headless ops. See [admin-auth/PRD.md](admin-auth/PRD.md).

- [ ] Admin realm + role + clients seed (`admin` realm, realm role `admin`, clients `admin-ui`/`ci-deployer`) — [admin-auth #01](admin-auth/issues/01-seed-admin-realm.md)
- [ ] JWT admin auth (dual-mode): `Authorization: Bearer <JWT>` with `admin` role check via `TokenValidator`; static `X-Admin-Key`/`Bearer api_key` retained **only** for `/admin/migrations/*` + `/admin/maintenance/cleanup` (offline `offline_access` token also accepted) — [admin-auth #02](admin-auth/issues/02-jwt-admin-middleware.md)
- [ ] Migrate ops auth from api_key to offline token — [admin-auth #03](admin-auth/issues/03-narrow-static-and-docs.md) (depends on F-19 for cleanup shape)

## Scopes & Roles

Scope/role model and mapping, Keycloak-style. See `.scratch/scopes/PRD.md`.

- [x] Well-known `scope_supported` derived from realm scopes ([#01](scopes/issues/01-well-known-from-realm-scopes.md))
- [x] Client scopes: per-client allow-list (`clients.scope`, NULL = inherit realm) via `ScopeResolver`, gates `offline_access` per client ([#02](scopes/issues/02-client-scopes-and-roles.md))
- [x] Client roles: per-client authorization namespace (`resource_access.<client>.roles`) — shipped with [#02](scopes/issues/02-client-scopes-and-roles.md) (2026-08-21)
- [x] Scope↔role mapping, Keycloak-style ([#03](scopes/issues/03-scope-role-mapping.md)) — done 2026-08-26
- [x] Admin API config surface for scopes/roles/mappings ([#04](scopes/issues/04-admin-api-configuration.md)) — done 2026-08-26

## Login Methods

- [x] Client Credentials grant (`grant_type=client_credentials`)
- [ ] Resource Owner Password grant (`grant_type=password`)
- [ ] Email magic link (`Mailer` interface + `NativeMailer` adapter)
- [ ] Email verification flow (one-time link flips `email_verified`) — **blocked until the Mailer lands** — [email-verification/PRD.md](email-verification/PRD.md)
- [ ] SMTP adapter (future VPS deployment)
- [ ] Social login (generic OAuth2 adapter for Google, GitHub, GitLab)
- [ ] 2FA/TOTP (authenticator app)

## Token Lifecycle & Offline Tokens

See [token-lifecycle/PRD.md](token-lifecycle/PRD.md) for the detailed situation.

- [x] Token Introspection (`POST /token/introspect`, RFC 7662)
- [x] Token Revocation (`POST /realms/{realm}/protocol/openid-connect/revoke`, RFC 7009)
- [x] Token blacklist table
- [x] Offline access: long-living refresh token when `offline_access` granted (realm-config offline TTL; dedicated per-client `offline_sessions`; survives SSO logout) — **prod requires scopes #02 first** — [#03](token-lifecycle/issues/03-offline-token-support.md)
- [ ] User consent screen for privileged scopes (`offline_access`, `prompt=consent`) — **planned, can be delayed**; client gating (scopes #02) is the control until then
- [x] Offline revocation — admin-initiated revoke-by-user/session, deferred to Admin API — [#04](token-lifecycle/issues/04-offline-revocation.md) (done 2026-08-23)
- [ ] Cleanup task: purge blacklist + expired sessions — admin-triggered (manual / deploy-time / CI-scheduled), owned by Admin API — [#05](token-lifecycle/issues/05-cleanup-job.md)

## Customizable Login Form

- [ ] Per-realm login page config (logo, colors, title, custom CSS)
- [ ] Google-style modal widget (SAM iframe)
- [ ] Fallback full-page form

## Refactor (Wave 2)

- [x] **Container kernel + remove DataSource** ([#07](issues/07-container-kernel.md))
- [x] **Split AuthorizeService** into InputValidator + SessionOrchestrator + AuthenticationOrchestrator
- [x] **Unified Slim wiring** — `src/App/AppBuilder` shared by entrypoint and TestAppFactory (clean-code #01, 2026-08-25)

## PHP 8 / PHPStan

- [x] Enums (LoginStatus, LoginEvent)
- [x] `GrantType` enum (Client Credentials)
- [ ] Remaining domain enums (ResponseMode, etc.)
- [ ] Readonly properties, constructor promotion
- [ ] Named arguments, match expressions
- [ ] PHPStan level 5 → 6 → 7 → 8 → 9 (incrementally)
- [ ] PSR12 compliance throughout
