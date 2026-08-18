# Backlog — priorities + allocation policy

Single source of truth for what to work on next. **Local by design** (3 machines, no remote tracker, no `gh`/2FA) — do not "improve" this into GitHub Issues until that constraint changes.

- Detail docs stay colocated in their feature dirs (`.scratch/<feature>/`); this table only links to them.
- Edit the table to re-rank. **Done = delete the row** (git history keeps everything).
- `ROADMAP.md` stays as the product direction; this file is the executable queue.

## Policy

- **Priority drives order**: P0 (security/correctness) → P1 → P2 → P3.
- **Allocation**: when picking a week/sprint of work, target **~70% feature / ~30% refactor by size**. P0 fixes (`type=fix`) preempt the split and don't count against either bucket.
- Pick features and refactors independently from their priority order, then balance the split.

## Queue (ranked)

| ID | Type | Priority | Size | Blocked by | Why-now | Doc |
|----|------|----------|------|------------|---------|-----|
| F-27 | fix | P1 | M | | RFC 6749 §5.2 error codes/statuses (D-01) | `oidc-compliance/PRD.md` |
| F-28 | fix | P1 | S | | `Cache-Control: no-store` + `Pragma` on token responses (D-02) | `oidc-compliance/PRD.md` |
| F-29 | fix | P1 | S | | reject `response_type != code` (D-03) | `oidc-compliance/PRD.md` |
| F-30 | fix | P1 | S | | revocation 401 on failed client auth (D-07) | `oidc-compliance/PRD.md` |
| F-31 | fix | P1 | M | | nonce/state/response_mode optional for code flow (D-04) | `oidc-compliance/PRD.md` |
| F-32 | fix | P1 | S | | `prompt=login` forces re-auth; don't silently ignore consent (D-05) | `oidc-compliance/PRD.md` |
| F-33 | fix | P1 | M | | exact `redirect_uri` matching (D-06) | `oidc-compliance/PRD.md` |
| F-34 | fix | P1 | S | | truthful discovery: `scopes_supported` + stop over-advertising (D-08/D-09) | `oidc-compliance/PRD.md` |
| F-35 | fix | P1 | S | | model `jsonSerialize` uses `get_object_vars` → leaks password hash on direct serialization (whitelist maps) | `clean-code/issues/09-…` |
| R-03 | refactor | P1 | L | | AuthOrchestrator: 9 deps, 10 jobs | `clean-code/issues/03-…` |
| F-04 | feature | P1 | M | | client roles namespace (`resource_access.<client>`) | `scopes/` |
| F-05 | feature | P1 | L | F-04 | scope↔role gating at issuance (needs `roles` tables from F-04) | `scopes/issues/03-…` |
| F-06 | feature | P1 | S | | offline revocation remainder: single-offline-session admin surface (list/revoke one session) + optional access-token bulk invalidation — revoke-by-user already shipped; admin CRUD exists, unblocked | `token-lifecycle/issues/04-…` |
| R-04 | refactor | P2 | S | | Basic-auth block ×3 in controllers | `clean-code/issues/05-…` |
| R-05 | refactor | P2 | S | | drop dead `InputValidator` DI entry (static conversion done) | `clean-code/issues/07-…` |
| R-06 | refactor | P2 | M | | untyped getters, mixed naming | `clean-code/issues/06-…` |
| F-07 | feature | P2 | M | | audit log table + query | `ROADMAP → Admin API` |
| F-36 | fix | P2 | S | | `TokenService::createKeys` unchecked openssl/mkdir/file I/O (fail fast at `POST /admin/keys`) | `clean-code/issues/10-…` |
| F-08 | feature | P2 | S | | ROPC grant | `ROADMAP → Login Methods` |
| F-09 | feature | P2 | M | | email magic link | `ROADMAP → Login Methods` |
| F-10 | feature | P2 | M | | consent screen (`offline_access`) — delayed by design; client gating (scopes #02) is the control until then | `ROADMAP → Token Lifecycle` |
| F-11 | feature | P2 | S | | per-realm password policy | `ROADMAP → Admin API` |
| F-12 | feature | P2 | M | F-04 | admin config surface for scopes/roles (roles CRUD from F-04; mappings after F-05) | `scopes/issues/04-…` |
| F-13 | feature | P2 | S | | per-realm login page config | `ROADMAP → Login Form` |
| F-19 | feature | P2 | S | | blacklist purge + expired-session cleanup | `token-lifecycle/issues/05-…` |
| F-20 | feature | P2 | M | | merge the two E2E scripts — deferred (both scripts still cover the same flow) | `ci-e2e/issues/01-…` |
| R-07 | refactor | P3 | L | | duplicate Slim wiring `index.php`/`TestAppFactory` | `clean-code/issues/01-…` |
| R-08 | refactor | P3 | S | | remaining domain enums (`ResponseMode`) | `ROADMAP → PHP 8` |
| R-09 | refactor | P3 | M | | readonly props + constructor promotion | `ROADMAP → PHP 8` |
| R-10 | refactor | P3 | M | | named args + match expressions | `ROADMAP → PHP 8` |
| R-11 | refactor | P3 | L | | PHPStan 5→6→7→8→9 | `ROADMAP → PHPStan` |
| F-14 | feature | P3 | S | | fallback full-page login form | `ROADMAP → Login Form` |
| F-15 | feature | P3 | L | | social login (Google/GitHub/GitLab) | `ROADMAP → Login Methods` |
| F-16 | feature | P3 | L | | 2FA/TOTP | `ROADMAP → Login Methods` |
| F-17 | feature | P3 | L | | Google-style modal widget (SAM iframe) | `ROADMAP → Login Form` |
| F-18 | feature | P3 | S | | SMTP adapter (VPS) | `ROADMAP → Login Methods` |

**Blocked-by:** empty = pickable now; a task ID = wait for that task first.
Conscious postponements (delayed/deferred) are flagged in Why-now, not as a
status.

## Done handling

Done rows are deleted from the queue; the linked detail docs stay in their feature dirs and git history retains everything. Archive zips are unnecessary — revisit only if `.scratch/` grows unwieldy.
