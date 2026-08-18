# Token Lifecycle & Offline Tokens

## Problem Statement

The server issues a refresh token on every auth-code login and supports the
full RFC 7009 / RFC 7662 lifecycle (revocation, introspection, blacklist). This
block was built as the foundation for an **offline token flow**: a client keeps
getting tokens after the user has gone away. The lifecycle mechanics are in
place, but the offline token model is only partially explicit:

- Refresh tokens exist, but nothing is tied to the OIDC `offline_access` scope.
  Realms can already accept it (scope validation runs against `realms.scope`),
  but no explicit support or semantics hang off it.
- There is no way to revoke tokens when the user is **not present** (no
  revoke-by-user, no revoke-by-session, no admin "logout everywhere").
- The blacklist grows unbounded and there is no cleanup yet; the target shared
  server cannot run cron, so cleanup must be an admin-triggered maintenance
  task (manual, at deployment time, or CI-scheduled) rather than a daemon.

## Current State (verified)

| Capability | Where | Status |
|---|---|---|
| Refresh token issued on auth_code | `TokenService::createRefreshToken` (realm `refresh_token_expires_in`) | Done |
| Refresh grant `grant_type=refresh_token` | `TokenGrantService::getTokensByRefreshToken` — DB is source of truth, token rotation, session + expiry checks | Done |
| Revoke refresh token → login `EXPIRED` + session `EXPIRED` | `TokenRevocationService` + `LoginStateMachine::doExpire` | Done |
| Revoke access token → jti blacklist | `TokenRevocationService` + `TokenBlacklistRepository` | Done |
| Introspection (RFC 7662), refresh + access paths | `TokenIntrospectionService` | Done |
| Access validation honors blacklist | `ValidateAccessToken` middleware | Done |
| `offline_access` accepted per realm | validated against `realms.scope` (auth-code + client_credentials); `scope_supported` derived from it (`OidcController::sendConfig`) | Works by config, not explicit |
| `offline_access` per-client allow-list | `clients.scope` | Missing — scopes PRD phase 2 (#02) |
| Offline revocation (admin, no token present) | `POST /admin/sessions/invalidate` expires user/client `offline_sessions`; delete guards (409) on active offline grants | Partial — revoke-by-user done with F-02; single-session surface + token bulk-invalidation in #04 |
| Blacklist + expired-session cleanup | — | TODO — admin-triggered maintenance task (Admin API) |

## The model

- **Offline token** = a refresh token usable after the user is gone, within the
  realm-configured TTL, rotating on every use, individually revocable.
- **`offline_access` scope** = the OIDC-standard signal for offline capability.
  Explicit support means:
  1. *Accepted when the realm allows it* — already works today by config.
  2. *Per-client allow-list* — `clients.scope` in scopes PRD phase 2 (#02);
     nothing to build in this workstream.
  3. *Offline refresh token semantics* — **in scope (the core feature)**: when a
     login is granted `offline_access`, the grant becomes a dedicated
     per-client `offline_sessions` record (offline access is client-bound,
     unlike the realm-wide SSO session) with a realm-configured offline TTL,
     exchanged for short-lived access tokens and independent of the SSO
     session/logout. Bounded (no expiry-less tokens). Implemented in
     [#03](issues/03-offline-token-support.md).
- **Offline revocation** = invalidating a user's tokens when the user is **not
  present**, including their `offline_sessions` (which survive SSO logout by
  design). Requires admin CRUD over users, sessions and `offline_sessions`
  first — it belongs to the Admin API workstream, not the OIDC protocol
  endpoints.

## Decisions / Non-goals

- **No permanent refresh tokens (for now).** A security/product decision —
  longer-lived refresh tokens widen the leak window. Not an infrastructure
  constraint: cleanup exists via admin tools, so TTLs do not depend on a cron
  daemon.
- **Cleanup delivered as an admin-triggered maintenance task**, not a cron job.
  Invoked manually, at deployment time, or from a scheduled CI step (GitHub
  Actions) when available. Owned by the Admin API workstream.
- **Offline revocation deferred to the Admin API** track. The existing RFC 7009
  endpoint already covers the online case (client has the token + credentials).
- **SSO reuse for offline grants (no re-auth), gated by per-client allow-list.**
  An SSO'd user requesting `offline_access` is not asked for a password again;
  the offline token extends the single authentication event. Production use
  requires scopes #02 (client gating) to land first. Consent UI is planned but
  delayed — client gating is the required control until it lands.
- **Offline tokens: `typ: Offline`, realm-config TTL defaulting to 30 days.**
  Bounded (no expiry-less tokens); introspection/revoke route `typ: Offline` as
  a refresh token. `end_session` is SSO-scoped and never touches
  `offline_sessions`. Details in [#03](issues/03-offline-token-support.md).

## Issues

- [#01](issues/01-revocation-endpoint.md) — Revocation endpoint (RFC 7009) — DONE
- [#02](issues/02-introspection-endpoint.md) — Introspection endpoint (RFC 7662) — DONE
- [#03](issues/03-offline-token-support.md) — Offline access: long-living refresh token (realm-config TTL; per-client gating in scopes #02)
- [#04](issues/04-offline-revocation.md) — Offline revocation (admin-initiated; deferred to Admin API)
- [#05](issues/05-cleanup-job.md) — Cleanup task (blacklist + expired sessions) — admin-triggered, owned by Admin API
