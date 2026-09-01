# F-07: Audit Log

## Status

PLANNED

## Summary

Add an append-only `audit_logs` table and read+purge admin API endpoints. Admin write actions (create/update/delete on realms, clients, users, roles, scope-role mappings) are recorded with the request payload as detail.

## Decisions

- **Capture**: explicit `AuditLogRepository::create()` calls inside each `AdminService` write method (not middleware — access logs already cover coarse request logging)
- **Detail**: request payload (JSON). No before/after diff (too verbose for MVP).
- **Retention**: permanent. Manual purge via dedicated `DELETE /admin/audit-logs` endpoint.
- **Scope**: admin API write paths only. Login flow, token issuance, etc. are out of scope.
- **Purge ownership**: lives in F-07 (not F-19) since it's audit-log-specific. F-19 stays focused on token blacklist + expired sessions.

## Schema (migration 009)

```sql
CREATE TABLE audit_logs (
    id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    actor_type TEXT NOT NULL,          -- 'admin_user' | 'api_key'
    actor_id TEXT,                     -- sub claim or NULL for api_key
    realm_id TEXT,                     -- which realm was affected (NULL for cross-realm ops)
    target_type TEXT NOT NULL,         -- 'user', 'client', 'realm', 'role', 'scope_role'
    target_id TEXT,                    -- UUID of the affected entity
    detail TEXT,                       -- JSON: request payload
    created_at TEXT NOT NULL
);

CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_actor ON audit_logs(actor_type, actor_id);
CREATE INDEX idx_audit_logs_target ON audit_logs(target_type, target_id);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_realm ON audit_logs(realm_id);
```

### Down migration

```sql
DROP INDEX IF EXISTS idx_audit_logs_realm;
DROP INDEX IF EXISTS idx_audit_logs_created;
DROP INDEX IF EXISTS idx_audit_logs_target;
DROP INDEX IF EXISTS idx_audit_logs_actor;
DROP INDEX IF EXISTS idx_audit_logs_action;
DROP TABLE IF EXISTS audit_logs;
```

## API

| Method | Path | Description | Params |
|--------|------|-------------|--------|
| `GET` | `/admin/audit-logs` | List (paged, filtered) | `action`, `actor_type`, `target_type`, `realm_id`, `from`, `to`, `limit`, `offset` |
| `GET` | `/admin/audit-logs/{id}` | Read single entry | — |
| `DELETE` | `/admin/audit-logs` | Purge by criteria | `realm_id`, `older_than` (ISO date) — at least one required; returns `{"deleted": N}` |

All endpoints require admin auth (JWT or static key).

### Purge validation

- At least one of `realm_id` or `older_than` must be provided → 400 if both null
- Returns count of deleted rows

## Files to create/modify

| File | Action |
|------|--------|
| `migrations/009_audit_log.up.sql` | **Create** |
| `migrations/009_audit_log.down.sql` | **Create** |
| `src/Models/AuditLogEntry.php` | **Create** — model + `AuditAction` backed enum |
| `src/Interfaces/AuditLogRepository.php` | **Create** |
| `src/Repositories/AuditLogRepository.php` | **Create** — `PagedListing` trait, filtered queries, `purge()` |
| `src/Controllers/Admin/AuditLogController.php` | **Create** — `list`, `read`, `purge` |
| `src/App/AppBuilder.php` | **Edit** — register 3 routes under `/admin/audit-logs` |
| `src/Config/Definitions.php` | **Edit** — bind `IAuditLogRepo` |
| `src/Services/RealmAdminService.php` | **Edit** — inject `AuditLogRepository`, log create/update/delete |
| `src/Services/ClientAdminService.php` | **Edit** — inject `AuditLogRepository`, log create/update/delete |
| `src/Services/UserAdminService.php` | **Edit** — inject `AuditLogRepository`, log create/update/delete |
| `src/Services/RoleAdminService.php` | **Edit** — inject `AuditLogRepository`, log create/update/delete |
| `src/Services/ScopeRoleAdminService.php` | **Edit** — inject `AuditLogRepository`, log create/update/delete |

## Service wiring

Each `AdminService` gets `AuditLogRepository` as a new constructor dependency. A private helper logs the event:

```php
private function audit(
    ServerRequestInterface $request,
    string $action,
    string $targetType,
    ?string $targetId,
    ?string $realmId = null,
): void {
    $this->auditLog->create(new AuditLogEntry(
        id: getGuid(),
        action: $action,
        actorType: $request->getAttribute('admin_claims') !== null ? 'admin_user' : 'api_key',
        actorId: $request->getAttribute('admin_user')?->id ?? null,
        realmId: $realmId,
        targetType: $targetType,
        targetId: $targetId,
        detail: json_encode($request->getParsedBody()),
        createdAt: sqlNow(),
    ));
}
```

Services that already receive the request pass it through. No signature changes beyond the new dependency.

## Actions to log

| Service | Action | Target Type |
|---------|--------|-------------|
| `RealmAdminService` | `realm.create`, `realm.update`, `realm.delete` | `realm` |
| `ClientAdminService` | `client.create`, `client.update`, `client.delete` | `client` |
| `UserAdminService` | `user.create`, `user.update`, `user.delete` | `user` |
| `RoleAdminService` | `role.create`, `role.update`, `role.delete` | `role` |
| `ScopeRoleAdminService` | `scope_role.create`, `scope_role.update`, `scope_role.delete` | `scope_role` |

## Model

```php
readonly class AuditLogEntry implements \JsonSerializable
{
    public function __construct(
        public string $id,
        public string $action,
        public string $actorType,
        public ?string $actorId,
        public ?string $realmId,
        public string $targetType,
        public ?string $targetId,
        public ?string $detail,
        public string $createdAt,
    ) {}

    public function jsonSerialize(): array { /* all fields */ }
}
```

`AuditAction` backed string enum with the 15 action values above.

## What's out of scope

- Middleware-based capture (redundant with access logs)
- Before/after diffs (too verbose for MVP)
- Auto-purge (manual via DELETE endpoint)
- Non-admin write paths (login flow, token issuance)
- Actor resolution beyond `sub` claim (sufficient for admin JWT + api_key)

## Testing

- Unit: `AuditLogRepository` — create, list with filters, read, purge
- Integration: `AuditLogController` — list/read/purge endpoints
- Integration: at least one `AdminService` (e.g. `UserAdminService`) — verify audit entry created on user create
