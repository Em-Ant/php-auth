# 04 — Offline revocation (admin-initiated)

status: **PARTIAL** — the revoke-by-user core landed with F-02; the rest stays deferred

## What landed with F-02 (2026-08-18)

`POST /admin/sessions/invalidate` now expires a user's/client's
`offline_sessions` (status = `EXPIRED`) in addition to deleting sessions and
logins, and user/client deletion guards on active offline grants (409) and
physically removes the expired rows. So "revoke user X → X's offline tokens
fail" already works through the admin API — see
[#03](03-offline-token-support.md#admin-api-integration-solved-with-f-02-not-deferred).

Still open (this issue): single-offline-session admin surface (list/revoke one
session), access-token bulk invalidation (jti registry or `nbf` enforcement),
and the offline-sessions purge in the cleanup task (#05).

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

This is why the roadmap item "Offline revocation" was not done: it presupposes
the Admin API CRUD track (users, sessions, offline sessions, realms/clients)
that does not exist yet.

## Scope (when Admin API lands)

- Admin endpoint to revoke all sessions + logins for a user **and all of that
  user's `offline_sessions`** (sets them all `EXPIRED`) — this is the real
  "offline revocation", since offline tokens are independent of the SSO session.
- Admin endpoint to revoke a single SSO session (expires the session + its
  logins). `offline_sessions` are **not** affected — per-client, independent by
  design.
- Optional: access-token invalidation for already-issued access tokens (minted
  from SSO or offline refresh) — either (a) store issued jtis per
  session/offline session, or (b) add a `not-before-policy`/`nbf` claim per
  user/session and enforce it at validation. Today tokens carry no `nbf`;
  responses echo `not-before-policy: 0` but nothing enforces it.
- Protected by the existing admin auth middleware + rate limiting.

## Ownership

Admin API workstream (roadmap "Admin API"), **not** the OIDC protocol
endpoints. Re-open/implement after admin CRUD for users, sessions and
`offline_sessions` exists.

## Acceptance (sketch)

- Admin revokes user X → all X's active sessions, logins **and offline tokens**
  fail (refresh → `invalid_grant`; introspection → `active: false`).
- Admin revokes SSO session S → S's logins/tokens die; X's offline tokens stay
  valid.
