# 02 — Session/login management, user deactivation, active-only delete guards

status: **DONE** 08/18/2026 (commit `dbb8826` — `feat: admin crud api (#3)`)

## Target behaviour

Admin surface over `sessions` and `logins` (the SSO side of offline
revocation), plus user deactivation:

- `GET /admin/sessions` — list (`?realm_id=`, `?user_id=`).
- `DELETE /admin/sessions/{id}` — delete a session (cascades its logins).
- `POST /admin/sessions/invalidate` — mark a user's/client's sessions
  `ACTIVE → EXPIRED` (with their logins).
- `GET /admin/logins` — list (`?realm_id=`, `?client_id=`).
- `DELETE /admin/logins/{id}` — delete a single login.
- User deactivation via `PUT /admin/users/{id}` `{ "valid": "FALSE" }`; disabled
  users fail login with `"user is disabled"`.
- Delete guards count **active** resources only: a client with only expired
  logins or a user with only expired sessions can be deleted.

## Remaining scope (separate follow-ups)

`offline_sessions` do **not** exist yet — that revocation is the offline token
workstream (token-lifecycle #03 then #04).