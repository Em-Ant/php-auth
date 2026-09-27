# Domain model — what the admin UI is actually editing

**Companion to [API-CONTRACT.md](API-CONTRACT.md)**. The contract tells you the shape of each
response. This tells you what the objects *mean*, how they relate, and which destructive
action will be refused. Getting this wrong costs structural rework in the navigation and
detail pages, so read it before designing the screens.

---

## 1. The one-sentence model

A **realm** is a hard tenant boundary. Everything else belongs to exactly one realm, nothing
crosses between realms, and clients and users are how the outside world enters.

```
Realm ──┬── Client ──┬── ScopeRoleMapping ──▶ Role
        │            └── Login ─────────────▶ Session ──▶ User
        ├── User ────┬── Session
        │            ├── OfflineSession
        │            └──▶ Role              (many-to-many, same realm only)
        └── Role
```

---

## 2. Entities

### Realm — the tenant

The unit of isolation and the unit of configuration. Owns the key set (`keys_id`), all the
token TTLs, the scope catalog, and the password policy. **Realms do not nest and nothing
crosses a realm boundary** — not roles, not clients, not sessions. This is enforced, not
conventional: assigning a role from another realm to a user returns `400`, and the error is
deliberately identical for "no such role" and "wrong realm" so the endpoint cannot be used to
enumerate other realms' role ids.

### Client — an application that asks for tokens

Either **public** (`require_auth: false`, browser-based, must use PKCE) or **confidential**
(`require_auth: true`, server-side, authenticates with a secret and can use
`client_credentials`). The `uri` field is a redirect-URI *pattern*, not a single URL.

### User — a person

Identified by `(email, realm_id)`. Two independent switches:

- `valid` — `false` deactivates the account. The user cannot log in, but the row and all its
  history remain. This is the "disable" action, not "delete".
- `email_verified` — defaults to **`true`** on creation. There is no verification flow yet, so
  this field is currently only meaningful once the email-verification feature ships.

### Role — a named grant

Belongs to a realm, and optionally to a client. A role with `client_id: null` is a **realm
role**; with a `client_id` it is a **client role**, scoped to that one client. Users hold
roles many-to-many. Roles are what the scope-to-role mappings hand out.

### The three session-shaped things

This is the single most important distinction in the whole model, and the most common source
of a wrong admin screen:

| Resource | What one row is | Created when | Ends when | Survives SSO logout |
|---|---|---|---|---|
| **Login** | one authentication *attempt* against one client | `/auth` is called | exchanged for tokens, or expires | no |
| **Session** | one SSO login — "this browser is signed in as this user" | the login is authenticated | idle/max TTL, or explicit revoke | n/a — it *is* the SSO thing |
| **Offline session** | one long-lived refresh grant — "this app may re-authenticate without a browser" | tokens issued with `offline_access` | its own offline TTL, or explicit revoke | **yes** |

A **Login** is therefore *not* a session: `PENDING` and `AUTHENTICATED` logins have not
become a session yet. For a "who is currently signed in" screen use **sessions**. For a "sign-in
activity / audit trail" screen use **logins**. For a "which apps still have standing access"
screen use **offline sessions** — that is the one an operator needs when revoking access, and
the only one that outlives logging out.

The offline session's `id` doubles as the `sid` claim in the tokens, so it is the handle to
show an operator.

---

## 3. Token lifetimes

Seven TTLs on the realm, and an operator will eventually ask "why did my session end". This
table is the answer. Defaults shown are the create-time defaults.

| Field | Default | Governs |
|---|---|---|
| `access_token_expires_in` | `300` | how long an access token is valid |
| `refresh_token_expires_in` | `1800` | how long a normal refresh token is valid |
| `pending_login_expires_in` | `300` | an authentication attempt that was never completed |
| `authenticated_login_expires_in` | `300` | an authenticated login not yet exchanged for tokens |
| `session_expires_in` | `86400` | maximum SSO session lifetime regardless of activity |
| `idle_session_expires_in` | `1800` | SSO session inactivity timeout |
| `offline_refresh_token_expires_in` | `2592000` (30 days) | offline/standing access |

`session_expires_in` is the ceiling and `idle_session_expires_in` the inactivity cutoff — a
session ends at whichever comes first. Surfacing both in the realm form with those two labels
("maximum lifetime" / "idle timeout") saves support questions later.

---

## 4. What blocks a delete

**Verified against the service layer, not inferred.** Every one of these returns `409` with
the reason in `error_description`. Show the reason to the operator; do not retry.

| Action | Refused while | Reason string starts with |
|---|---|---|
| `DELETE /admin/realms/{id}` | the realm has **any client or any user** | `realm '…' still has clients or users` |
| `DELETE /admin/clients/{id}` | the client has **active logins** | `client '…' still has active logins` |
| `DELETE /admin/clients/{id}` | the client has **active offline sessions** | `client '…' still has active offline sessions` |
| `DELETE /admin/users/{id}` | the user has an **active session** | `user '…' still has active sessions` |
| `DELETE /admin/users/{id}` | the user has an **active offline session** | `user '…' still has active offline sessions` |
| `DELETE /admin/roles/{id}` | the role is **assigned to users** | `role '…' is still assigned to users` |
| `DELETE /admin/roles/{id}` | the role is **referenced by a scope-role mapping** | `role '…' is still referenced in scope-role mappings` |

The guard is on *active* things. Expired logins, sessions, and offline sessions do not block
a delete — expired offline rows are removed automatically as part of the cascade. So "delete
fails" usually means "revoke first", and the UI should offer that as the next step rather than
just showing an error.

**Never blocked** — these always succeed, so the UI can call them without pre-checking:

| Action | Note |
|---|---|
| `DELETE /admin/sessions/{id}` | cascades to the session's logins |
| `DELETE /admin/logins/{id}` | plain row removal |
| `DELETE /admin/offline-sessions/{id}` | **a revoke, not an erase** — the row stays, `status` becomes `EXPIRED`, still listable |
| `DELETE /admin/users/{id}/roles/{role_id}` | idempotent: `204` even if not assigned |
| `DELETE /admin/clients/{id}/scope-roles/{scope}/{role_id}` | idempotent: `204` even if absent |

**One guard is a `400`, not a `409`:** `DELETE /admin/audit-logs` requires at least one of
`realm_id` or `older_than`. A purge can never be unbounded by accident.

### The order of operations for a clean delete

Because of the guards, "remove this user completely" is a sequence, not one call:

1. `POST /admin/sessions/invalidate` with `user_id` — expires offline grants and sessions, and
   returns the count.
2. Then `DELETE /admin/users/{id}`.

Same for a client: invalidate its logins/offline grants first, then delete. Build this as a
single "revoke and delete" action in the UI rather than making the operator discover the order.

---

## 5. Reference vocabularies

Exact values for dropdowns, badges, and filters. Do not invent values — an unrecognised value
in a filter silently returns nothing, because out-of-range query values fall back to their
default.

**Session `status`** — `ACTIVE`, `EXPIRED`

**Login `status`** — `PENDING` (attempt not completed), `AUTHENTICATED` (completed, no tokens
yet), `ACTIVE` (tokens issued), `EXPIRED`

**Offline session `status`** — `ACTIVE`, `EXPIRED`

**Audit `action`** — `realm.create`, `realm.update`, `realm.delete`, `client.create`,
`client.update`, `client.delete`, `user.create`, `user.update`, `user.delete`, `role.create`,
`role.update`, `role.delete`, `scope_role.create`, `scope_role.update`, `scope_role.delete`

**Audit `actor_type`** — `admin_user` (a JWT admin logged in) or `api_key` (the static key)

**Audit `target_type`** — `realm`, `client`, `user`, `role`, `scope_role`. For `scope_role`
actions the `target_id` is the **role id**, not the client id.

**`acr`** — an authentication-context string. `"0"` means no special context. The dashboard
should render it as an opaque badge and not attach meaning to it.

**Scopes** — there is **no scopes endpoint**. The available scopes for a realm are exactly the
space-delimited words in that realm's `scope` field, and a client may narrow it further with
its own `scope`. Build the scope picker by splitting on a single space, then intersecting with
the selected client. `offline_access` is an ordinary scope string here, gated per client by
that allow-list — a client without it cannot obtain an offline token.

**Password policy** — `min_length`, `min_lower`, `min_upper`, `min_digits`, `min_special`, each
a non-negative integer where **`0` disables that rule** and **`null` means inherit** the global
config. A realm showing `null` is not "no policy", it is "not overriding". The UI must
distinguish those three states per rule, and must send an explicit `null` to clear an override
(omitting the field means "leave it alone").

---

## 6. Suggested screen map

Derived from the model, so the navigation reflects the real hierarchy:

- **Realms** (list) → realm detail with tabs: Overview/TTLs, Password policy, Clients, Users,
  Roles. Everything hangs off a realm, so making the realm the top-level context is the
  natural fit.
- **Clients** → client detail: config, **secret** (reveal-once, generate client-side), and
  **Scope-to-role mappings** (a child resource of the client).
- **Users** → user detail: profile, **roles** (a child resource of the user), and a
  "standing access" panel showing sessions and offline sessions.
- **Sessions / Logins / Offline sessions** → three separate screens, or one screen with a
  type switch. They answer different questions; do not merge them into one table.
- **Audit log** → global, filterable by action, actor, target, realm, date range.

---

## 7. Invariants worth encoding in the UI

1. **Realms are hard tenants.** Never offer a role from another realm in an assign-role picker; filter by the user's realm client-side.
2. **A client secret is write-only.** Generate it in the form, show it once, never expect to read it back.
3. **`valid: false` is not a delete.** Deactivate is reversible; delete is guarded and often blocked. Both belong in the UI, with different labels and different confirmations.
4. **Revoke before delete.** Wire the invalidate call into the delete flow.
5. **Absent, `null`, and `0` are three different things** everywhere — most obviously in the password policy.
6. **Read `limit` back from every list response** rather than assuming the value you sent.
7. **Empty filter results usually mean a bad filter value**, not an empty table, because out-of-range values silently become defaults.
