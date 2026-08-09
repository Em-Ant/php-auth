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

| ID | Type | Priority | Size | Status | Why-now | Doc |
|----|------|----------|------|--------|---------|-----|
| R-03 | refactor | P1 | L | ready | AuthOrchestrator: 9 deps, 10 jobs | `clean-code/issues/03-…` |
| F-02 | feature | P1 | L | ready | offline_access core feature; scopes #02 done, unblocked | `token-lifecycle/issues/03-…` |
| F-03 | feature | P1 | L | backlog | admin CRUD unblocks the admin-side items below | `ROADMAP → Admin API` |
| F-04 | feature | P1 | M | backlog | client roles namespace (`resource_access.<client>`) | `scopes/` |
| F-05 | feature | P1 | L | backlog | scope↔role gating at issuance | `scopes/issues/03-…` |
| F-06 | feature | P1 | M | backlog | admin-initiated offline revocation | `token-lifecycle/issues/04-…` |
| R-04 | refactor | P2 | S | ready | Basic-auth block ×3 in controllers | `clean-code/issues/05-…` |
| R-05 | refactor | P2 | S | ready | static `InputValidator` + dead DI entry | `clean-code/issues/07-…` |
| R-06 | refactor | P2 | M | ready | untyped getters, mixed naming | `clean-code/issues/06-…` |
| F-07 | feature | P2 | M | backlog | audit log table + query | `ROADMAP → Admin API` |
| F-08 | feature | P2 | S | backlog | ROPC grant | `ROADMAP → Login Methods` |
| F-09 | feature | P2 | M | backlog | email magic link | `ROADMAP → Login Methods` |
| F-10 | feature | P2 | M | delayed | consent screen (`offline_access`) | `ROADMAP → Token Lifecycle` |
| F-11 | feature | P2 | S | backlog | per-realm password policy | `ROADMAP → Admin API` |
| F-12 | feature | P2 | M | backlog | admin config surface for scopes/roles | `scopes/issues/04-…` |
| F-13 | feature | P2 | S | backlog | per-realm login page config | `ROADMAP → Login Form` |
| F-19 | feature | P2 | S | backlog | blacklist purge + expired-session cleanup | `token-lifecycle/issues/05-…` |
| F-20 | feature | P2 | M | deferred | merge the two E2E scripts | `ci-e2e/issues/01-…` |
| R-07 | refactor | P3 | L | backlog | duplicate Slim wiring `index.php`/`TestAppFactory` | `clean-code/issues/01-…` |
| R-08 | refactor | P3 | S | backlog | remaining domain enums (`ResponseMode`) | `ROADMAP → PHP 8` |
| R-09 | refactor | P3 | M | backlog | readonly props + constructor promotion | `ROADMAP → PHP 8` |
| R-10 | refactor | P3 | M | backlog | named args + match expressions | `ROADMAP → PHP 8` |
| R-11 | refactor | P3 | L | backlog | PHPStan 5→6→7→8→9 | `ROADMAP → PHPStan` |
| R-12 | refactor | P3 | S | backlog | PSR-12 verify (PHPCS green; checkbox may be stale) | `ROADMAP → PHP 8` |
| F-14 | feature | P3 | S | backlog | fallback full-page login form | `ROADMAP → Login Form` |
| F-15 | feature | P3 | L | backlog | social login (Google/GitHub/GitLab) | `ROADMAP → Login Methods` |
| F-16 | feature | P3 | L | backlog | 2FA/TOTP | `ROADMAP → Login Methods` |
| F-17 | feature | P3 | L | backlog | Google-style modal widget (SAM iframe) | `ROADMAP → Login Form` |
| F-18 | feature | P3 | S | backlog | SMTP adapter (VPS) | `ROADMAP → Login Methods` |

## Done handling

Done rows are deleted from the queue; the linked detail docs stay in their feature dirs and git history retains everything. Archive zips are unnecessary — revisit only if `.scratch/` grows unwieldy.
