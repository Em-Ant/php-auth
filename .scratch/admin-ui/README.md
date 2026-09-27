# Admin UI handoff

Documents for building the admin dashboard SPA in its own repo. Start here, in this order.

| Doc | Read it when | What it answers |
|---|---|---|
| **[GETTING-STARTED.md](GETTING-STARTED.md)** | first, before writing any code | How do I run the backend, what is already in the database, what are the dev credentials, how do I log in, and what do I do when it 401s |
| **[API-CONTRACT.md](API-CONTRACT.md)** | while building | Every endpoint: URL, request payload, response shape, headers, error slugs, filters, pagination rules |
| **[DOMAIN-MODEL.md](DOMAIN-MODEL.md)** | while designing screens | What the entities mean, how they relate, which deletes get refused, the exact enum values, a suggested screen map |

## The 60-second version

- The backend is ready. CRUD is complete across realms, clients, users, roles, scope-role
  mappings, sessions, logins, offline sessions, and the audit log. Nothing on the critical
  path is missing.
- Log in with **OIDC authorization code + PKCE** against the `admin` realm. Redirect the
  browser to `/auth`; the backend serves the login form. Do not build a login form in the SPA.
- Dev login is `admin@example.com` / `ChangeMe!dev`, already holding the `admin` role.
- The seeded `admin-ui` client already allows `http://localhost:5173/*`, the default Vite
  origin. No backend change is needed to start.
- Every `/admin/*` call needs `Authorization: Bearer <access_token>`. The access token lives
  **300 seconds** — build for that.
- Access tokens expire fast and the static key is being retired. Neither is a reason to wait;
  both are reasons not to put the token in `localStorage`.

## Before you start

Two things are worth knowing about the state of the backend, because they will look like bugs:

1. **All list endpoints — including `GET /admin/realms` — return the `{items, total, limit, offset}` envelope** (F-52 done). No special case.
2. **There is no free-text search.** Users and clients can only be filtered by `realm_id`.
   Tracked as F-53, planned as an additive change. If your table needs search, ask for it to be
   prioritised rather than building client-side search across paginated pages.

Both are listed with the rest in [API-CONTRACT.md §8](API-CONTRACT.md#8-known-gaps-to-raise-not-to-work-around).

## Source of truth

Every field in these documents was read out of the backend source at commit `006ff4b`, not out
of a design document. When the backend changes, these need updating — they are not generated,
they are maintained. The authoritative route table is `src/App/AppBuilder.php` in the
`php-auth` repo, and `bin/e2e-test.sh` contains a working scripted version of the whole OIDC
flow if you need a reference implementation of anything ambiguous.
