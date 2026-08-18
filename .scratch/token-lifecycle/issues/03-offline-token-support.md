# 03 — Offline access: long-living refresh token (Keycloak-compatible)

status: **DONE** — the core feature for `offline_access` (implemented 2026-08-18)

Implemented as designed below, with these choices:

- **OfflineSessionService** owns the offline lifecycle (create at code exchange,
  refresh with rotation + sliding TTL) so `TokenGrantService` stays thin; the
  `logins` row is left untouched (no refresh token, expires by its own timers).
- **Refresh dispatch** on the refresh token's `typ` claim (`Offline` →
  `offline_sessions`; otherwise the existing login flow) in
  `TokenGrantService::getTokensByRefreshToken`.
- **`offline_refresh_token_expires_in`** defaults to 30 days via migration and is
  editable through the admin realm CRUD (`optionalInt` in `RealmsController`).
- **TokenService** builds access/id/refresh claims from a shared grant context
  (`createTokenBundleFromContext`), so online and offline bundles share one set
  of claim creators; the offline refresh token carries `typ: Offline`.
- Revoke + introspect route `typ: Offline` to the DB lookup alongside
  `typ: Refresh`; `end_session` never touches `offline_sessions`.

Coverage: `OfflineAccessTest` (10 integration) + `OfflineSessionRepositoryTest` (8), plus an
E2E smoke step (`bin/e2e-test.sh` Step 24b) covering issue → rotate → introspect →
survive logout → revoke against the dev server, run on a throwaway admin realm that is
deleted afterwards (no dev-DB mutation).

## Admin API integration (solved with F-02, not deferred)

Deleting a user/client that still held offline grants would silently orphan
`offline_sessions` rows — a functional gap in the admin API. Closed the same way
sessions/logins are handled:

- `DELETE /admin/users/{id}` and `DELETE /admin/clients/{id}` return **409** while
  the user/client has **active** offline sessions (guard, mirror of the
  sessions/logins guards).
- `POST /admin/sessions/invalidate` **expires** the user's/client's offline
  sessions (`status = EXPIRED`) alongside deleting sessions + logins — the
  admin-initiated offline revocation path (RFC 7009 analog, no token needed).
- User/client delete physically removes the leftover (already-expired) offline
  rows, so no orphans survive and FK enforcement does not block the delete.
- Expired rows that are never deleted are the cleanup task's domain (#05).

Repo surface added: `countActiveByUserId/ClientId`, `setExpiredByUserId/ClientId`,
`deleteByUserId/ClientId` (+ integration tests in `AdminCrudTest`).

## Target behaviour (Keycloak parity, but bounded)

When a login is granted `offline_access`, the grant becomes a dedicated
**offline session** bound to one client:

- The refresh token is an **offline token**: long, realm-configured TTL
  (`offline_refresh_token_expires_in`, default 30 days), exchanged for
  short-lived access tokens (access-token TTL unchanged).
- Offline refresh tokens carry `typ: Offline` (Keycloak parity).
- The offline session is independent of the browser SSO session: no shared
  session, no `AUTH_SESSION` cookie, survives SSO logout.
- Still revocable: RFC 7009 revoke + introspection `active` both honor it.

## Model — a separate `offline_sessions` entity

Offline access is bound to a **client** (a refresh token belongs to one client ×
user × grant), whereas the SSO session is **realm-wide** (one session serves all
clients, hence `sessions` has no `client_id`). Offline grants therefore get
their own entity combining what `logins` + `sessions` hold separately today:

```sql
CREATE TABLE offline_sessions (
    id               VARCHAR(36)  PRIMARY KEY NOT NULL,   -- acts as sid
    realm_id         VARCHAR(36)  NOT NULL,
    user_id          VARCHAR(36)  NOT NULL,
    client_id        VARCHAR(36)  NOT NULL,               -- offline is per-client
    acr              VARCHAR(16)  NOT NULL DEFAULT '0',
    scope            VARCHAR(100) NOT NULL,               -- granted scope, incl. offline_access
    nonce            VARCHAR(256),                        -- kept for refresh-token claim parity
    refresh_token    VARCHAR(2048),                       -- current (rotated) token
    authenticated_at TIMESTAMP,
    created_at       TIMESTAMP    DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at       TIMESTAMP,                           -- last refresh (sliding offline TTL)
    status           VARCHAR(16)  DEFAULT 'ACTIVE',
    FOREIGN KEY (realm_id) REFERENCES realms(id),
    FOREIGN KEY (user_id)  REFERENCES users(id),
    FOREIGN KEY (client_id) REFERENCES clients(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS offline_sessions_token_ind ON offline_sessions (refresh_token);
CREATE INDEX IF NOT EXISTS offline_sessions_updated_ind ON offline_sessions (updated_at);
```

Deliberately **not** carried over from `logins`: `state`, `code`,
`code_challenge`, `csrf_token`, `redirect_uri`, `response_mode` — authorize-flow
artifacts that are irrelevant once the offline token exists. This mirrors
Keycloak's split between live sessions and offline sessions (offline user
session + offline client session; we collapse to one per client, which is
sufficient).

## Lifecycle

1. **Creation** — at auth-code exchange, if `login.scope` includes
   `offline_access`: create the `offline_sessions` row with the initial refresh
   token. The `logins` row is left alone (its `refresh_token` stays NULL and it
   expires by its own short timers).
2. **Refresh** — `findByRefreshToken` hits `offline_sessions` (fall back to
   `logins` for non-offline). Validate `status = ACTIVE` and
   `updated_at + offline_refresh_token_expires_in` (sliding). Rotate the
   `refresh_token` in place, bump `updated_at`, issue access/id tokens using
   claims from the offline session (`sid`, `acr`, `auth_time`, user).
3. **Revocation (RFC 7009)** — mark the row `EXPIRED`. Introspection routes
   offline tokens (`typ: Offline`) to the DB lookup, alongside `typ: Refresh`.
4. **Logout** — `end_session` is SSO-scoped only and never touches
   `offline_sessions`; offline tokens survive logout (Keycloak parity). They
   are revoked by the client via RFC 7009 or by an admin (#04).
5. **Cleanup (#05)** — purge `offline_sessions` where `status != 'ACTIVE'` or
   `updated_at + offline TTL < now`. Self-contained retention; no risk of
   deleting a session a live offline login references — it *is* the record.

## Decisions

- **SSO reuse kept (no re-auth).** An SSO'd user requesting `offline_access`
  is granted without a password prompt; the offline token extends the single
  authentication event. The load-bearing controls are per-client gating
  (`clients.scope`, scopes #02) and the realm's `scope` allow-list.
- **Consent UI planned but delayed.** No `prompt=consent` yet; until it lands,
  per-client gating is the required control.
- **Offline TTL default: 30 days.** `offline_refresh_token_expires_in`
  defaults to 30 days (Keycloak's Offline Session Idle default); admin can
  override per realm. No expiry-less tokens.
- **`typ: Offline` adopted** (Keycloak parity). Introspection and revoke
  routing must treat `typ: Offline` as a refresh token (DB lookup), in addition
  to `typ: Refresh`.
- **`end_session` is SSO-scoped only.** It never touches `offline_sessions`.
  Offline tokens are revoked via RFC 7009 (client holds the token) or the admin
  API (#04). Matches Keycloak (offline tokens survive logout) and OIDC
  (RP-initiated logout ends the session; token invalidation is RFC 7009).

## Deliberate non-goals

- **No permanent / expiry-less tokens.** Keycloak's `refresh_expires_in: 0`
  signalling is a known footgun (keycloak/keycloak#48063) — we keep a bounded,
  configurable offline TTL.

## Changes (touch points)

- Migration: `offline_sessions` table + indexes.
- Realm config: `offline_refresh_token_expires_in` (default 30 days, + admin
  edit surface).
- New `OfflineSession` model + `OfflineSessionRepository`
  (`create` / `findByRefreshToken` / `refresh` / `expire`).
- `TokenService`: offline token-bundle path (claims from offline session, TTL
  from offline config; `typ: Offline` marker on the refresh token).
- `TokenGrantService::getTokensByRefreshToken`: offline lookup first, offline
  lifecycle (no SSO session checks).
- `LoginStateMachine`: stays for `logins`; small parallel handling for offline
  rows (or generalize — decide at implementation).
- `TokenRevocationService` + `TokenIntrospectionService`: offline lookup branch;
  treat `typ: Offline` like `typ: Refresh` (DB lookup, not blacklist/signature).
- Tests: unit + integration (offline grant survives session expiry/logout;
  rotation; revoke; introspect; refresh never widens scope).

## Acceptance (sketch)

- Login with `scope=openid offline_access` → refresh token valid for the
  offline TTL (e.g. 30 days), exchangeable for short-lived access tokens.
- SSO session expires or user logs out → offline refresh still works.
- Login without `offline_access` → behaves exactly as today.
- Revoked offline token → refresh `invalid_grant`, introspection `active: false`.

## Depends on / sequencing

- **Scopes #02 (per-client gating) is a hard prerequisite for production.** Offline
  access must not ship to prod until clients can be allow-listed — with SSO
  reuse, any client would otherwise silently obtain long-lived tokens. Realm-level
  acceptance works as a dev milestone only.
- **Admin API realm CRUD** to configure the offline TTL (or a sensible default
  via migration/seed as a first step).
- **Consent UI** is a follow-up, can be delayed (see Decisions).
