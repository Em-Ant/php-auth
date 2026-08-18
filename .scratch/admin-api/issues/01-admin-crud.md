# 01 — Admin CRUD: realms, clients, users, key assignment

status: **DONE** 08/18/2026 (commit `dbb8826` — `feat: admin crud api (#3)`) — was the F-03 backlog item

## Target behaviour

A Bearer-protected `/admin` API (same middleware as `/admin/migrations`) that
manages the entities the OIDC flows consume:

- **Realms** — list, create (with `keys_id`), read, partial update, delete.
- **Clients** — list (filterable by realm), create, read, partial update,
  delete.
- **Users** — list (filterable by realm), create, read, partial update,
  delete.
- **Keys** — `POST /admin/keys` generates a fresh RSA key pair and returns the
  `kid` for key assignment.

See [PRD](../PRD.md) for the full contract table.

## Changes (touch points)

- `TokenService::createKeys()` — add `$keysRoot` param (honour configured
  `keys_root`) and return the generated `kid` (currently `void`, path is
  hardcoded `keys/<kid>`).
- Repositories + interfaces: `RealmRepository`, `ClientRepository`,
  `UserRepository` get `findAll` / `create` / `update` / `delete`;
  `ClientRepository::countByRealmId`, `UserRepository::countByRealmId`,
  `LoginRepository::countByClientId`, `SessionRepository::countByUserId` for
  delete guards.
- New controllers in `src/Controllers/Admin/`: `RealmsController`,
  `ClientsController`, `UsersController`, `KeysController`.
- `Definitions.php` — autowire the new controllers (`KeysController` needs
  `keys_root`).
- `public/index.php` + `tests/Support/TestAppFactory.php` — wire `/admin`
  routes behind `AdminMiddleware`; extend body-parsing middleware to accept
  `PUT` (currently POST-only).
- Tests: `tests/Integration/AdminCrudTest.php`.

## Acceptance (sketch)

- Unauthenticated / wrong token → 401.
- Create realm with a generated `keys_id` → realm readable, keys present.
- Create realm with unknown `keys_id` → 400.
- Duplicate realm name / client name+uri / user email-in-realm → 409.
- Client secret and user password are write-only; response carries
  `has_secret` instead of a hash; stored value verifies with
  `SecretsService::validatePassword`.
- DELETE of a realm with clients/users, client with logins, user with
  sessions → 409.
- PUT changes only provided fields.
- Storage failures → 500 via the existing `StorageFailed` handler.
