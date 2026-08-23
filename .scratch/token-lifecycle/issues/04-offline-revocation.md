# 04 — Offline revocation (admin-initiated)

status: **DONE** — 2026-08-23 (F-06)

- F-02 (2026-08-18): `POST /admin/sessions/invalidate` bulk-expires `offline_sessions` by `user_id`/`client_id`, 409 guards on active offline grants, deletes expired rows on user/client delete.
- F-06 (2026-08-23): single-offline-session admin surface — `GET /admin/offline-sessions` (filter `realm_id`/`user_id`/`client_id`, paginated `{items,total,limit,offset}`), `GET /admin/offline-sessions/{id}`, `DELETE /admin/offline-sessions/{id}` (`ACTIVE→EXPIRED`, idempotent 204). Verified by `bin/e2e-test.sh` Step 24c (two per-client grants, single revoke proves isolation, introspect/refresh, pagination).
- Access-token bulk invalidation (`nbf`/`not-before` per user) deliberately deferred — `5m` access-token window accepted; short-lived tokens + per-`jti` blacklist already cover the MUST. Revisit if `F-19` cleanup or prod policy requires it.

## What landed with F-02 (2026-08-18)

`POST /admin/sessions/invalidate` now expires a user's/client's
`offline_sessions` (status = `EXPIRED`) in addition to deleting sessions and
logins, and user/client deletion guards on active offline grants (409) and
physically removes the expired rows. So "revoke user X → X's offline tokens
fail" already works through the admin API — see
[#03](03-offline-token-support.md#admin-api-integration-solved-with-f-02-not-deferred).

Remainder closed by F-06; the offline-sessions purge lives in the cleanup task (#05).

## Situation

Today revocation requires **the token** AND **the requesting client's
credentials** (`POST /realms/{realm}/protocol/openid-connect/revoke`, RFC 7009).
There is no way to invalidate a user's tokens/sessions when the user is **not
present**:

- no revoke-by-session,
- no revoke-by-user ("logout everywhere"),
- the blacklist is per-`jti` only — a session's already-issued access tokens
  cannot be bulk-invalidated and keep validating until `exp`.

Once #03 lands, offline tokens (`offline_sessions`) survive SSO logout by
design, so the only ways to kill them are RFC 7009 (client holds the token) or
this admin surface.

This is why the roadmap item "Offline revocation" was not done earlier: it
presupposed the Admin API CRUD track (users, sessions, offline sessions,
realms/clients). That prerequisite is now met (`feat: admin crud api` +
offline-access commit), so the remaining surface is no longer blocked.

## Scope (shipped)

- Bulk revoke: `POST /admin/sessions/invalidate` revokes all sessions+logins **and** all `offline_sessions` for a user/client (`EXPIRED`). — F-02.
- Single SSO session: `DELETE /admin/sessions/{id}` cascades logins; `offline_sessions` unaffected (per-client independence). — pre-existing.
- Single offline session: `GET /admin/offline-sessions` + `GET /admin/offline-sessions/{id}` + `DELETE /admin/offline-sessions/{id}` — F-06.
- Optional access-token bulk invalidation (jti registry vs `not-before`) — deferred (see status).

All admin endpoints protected by `AdminMiddleware` + rate limiting.

## Ownership

Admin API workstream (roadmap "Admin API"), **not** the OIDC protocol
endpoints. Precondition met: admin CRUD for users, sessions and
`offline_sessions` shipped (`feat: admin crud api`). F-06 closes the remainder.

## Acceptance (verified)

- Admin bulk-invalidates user X → all X's active sessions, logins **and offline tokens** fail (refresh → `invalid_grant`; introspection → `active: false`). — F-02, `AdminCrudTest::testInvalidateExpiresOfflineSessionsAndUnblocksDeletion` + `e2e` Step 25.
- Admin revokes SSO session S → S's logins/tokens die; X's offline tokens stay valid. — `SessionsController::delete`.
- Admin lists offline sessions with `{items,total,limit,offset}` envelope, reads one, deletes one (`ACTIVE→EXPIRED` idempotent) → deleted refresh fails, sibling per-client grant stays valid, pagination `limit=1` respected. — `AdminOfflineSessionsTest` + `e2e` Step 24c.
