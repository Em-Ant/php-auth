# Issue KEY-P-01 — Offline grant `session_state` / `sid` vs check‑session iframe

- **Priority:** P2 (Keycloak parity / OIDC-correctness)
- **Status:** Partially implemented — see *Resolution* below
- **Component:** `src/Services/{TokenService,OfflineSessionService}.php`,
  `src/Models/GrantContext.php`, login‑status iframe (`public/login-iframe` path)
- **Parent:** `.scratch/keycloak-parity/PRD.md` — F‑38 (`session_state` parity)

## Resolution (implemented this session)

The auth‑code exchange that mints an offline grant now publishes the **online
SSO session id** (not the offline record id) as `session_state` / `sid`:

- `GrantContext::withSid(string $sid): self` — overrides the published `sid`
  without touching the grant's own session record.
- `TokenService::createOfflineTokenBundle(... string $sessionId): array` now
  takes the SSO session id to advertise and builds the context via
  `GrantContext::fromOfflineSession($offlineSession)->withSid($sessionId)`.
- `OfflineSessionService::createOfflineGrant` passes `$session->getId()` (the
  live online session) — the auth‑code / `offline_access` path.
- `OfflineSessionService::refreshOfflineGrant` passes
  `$offlineSession->getId()` (no live SSO session exists during a pure offline
  refresh, so the offline id is the only stable identifier available).

Regression test: `tests/Unit/Services/TokenServiceTest.php`
→ `testOfflineBundlePublishesOnlineSessionIdNotOfflineId` (online id published,
offline record id not leaked). Full suite green: 583 tests / 1695 assertions;
236 E2E passed; `composer stan` (L5) + PSR12 clean.

### Why this is sufficient for the iframe

The check‑session iframe hashes `session_state` and compares it to the
`AUTH_SESSION` cookie, which `HttpSessionCookieHandler::write()` derives as
`b64url(SHA‑256(onlineSessionId))`. The authorization redirect always writes
that cookie from the online session, so the published `session_state` must be
the online id. The offline session's own id stays internal (used only for
persistence/lookup; `sid` is never consumed by `TokenValidator`).

## Residual — requires a live Keycloak investigation

When an offline **refresh** is later performed against this server while the user
has **no live online SSO session** (pure `grant_type=refresh_token` with an
offline token, SSO session expired/revoked), the issued tokens' `sid` reverts to
the offline record id. We have **not** verified what Keycloak emits in that
exact scenario, because it requires:

1. A running Keycloak instance,
2. A pre‑existing offline token issued by that Keycloak,
3. The SSO session destroyed/rejected, then a refresh, then a check‑session
   probe with a valid `KEYCLOAK_SESSION` cookie absent.

That is a live‑system investigation (out of scope for the regression suite,
which runs against in‑memory SQLite + PHP built‑in server). Mark this item
**fixed** once the live probe confirms whether Keycloak's check‑session
`session_state` for a no‑SSO offline refresh should still reference the
(now‑gone) SSO session or the offline session.

## Notes / non‑goals

- By design this server is a functional subset of Keycloak, not a clone; parity
  gaps are opportunistic unless they break real clients or leak secrets.
- The first‑issuance path (above) already removes the observable mismatch
  between the auth response `session_state` and the token response `session_state`
  for the `auth‑code + offline_access` flow, which was the concrete bug surfaced
  by F‑38.
