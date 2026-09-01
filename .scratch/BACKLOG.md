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
| F-08 | feature | P2 | S | | ROPC grant | `ROADMAP → Login Methods` |
| F-11 | feature | P2 | S | | per-realm password policy | `ROADMAP → Admin API` |
| F-13 | feature | P2 | S | | per-realm login page config | `ROADMAP → Login Form` |
| F-19 | feature | P2 | S | | blacklist purge + expired-session cleanup | `token-lifecycle/issues/05-…` |
| F-45 | feature | P2 | S | | retire the `realm_roles` string field on user create/update (shim per ADR-0001 D4): breaking admin-API change; consumers must create roles explicitly then assign via `POST /admin/users/{id}/roles`; also removes `ensureRealmRole` auto-create | `docs/adr/0001 → Negative/follow-ups, F-45` |
| F-07 | feature | P2 | M | | audit log table + query | `ROADMAP → Admin API` |
| F-09 | feature | P2 | M | | email magic link | `ROADMAP → Login Methods` |
| F-10 | feature | P2 | M | | consent screen (`offline_access`) — delayed by design; client gating (scopes #02) is the control until then | `ROADMAP → Token Lifecycle` |
| F-20 | refactor | P2 | M | | split E2E into two contracts — prod smoke (`bin/smoke-test.sh`, no DB, bounded footprint, ~30 checks) + local OIDC integrity suite; phase 2: PHPUnit-against-live-`BASE_URL` (no Playwright) — also replaces the ad-hoc `python3` JWT payload decoding in `bin/e2e-test.sh` with PHP tooling | `ci-e2e/PRD.md` |
| F-14 | feature | P3 | S | | fallback full-page login form | `ROADMAP → Login Form` |
| F-18 | feature | P3 | S | | SMTP adapter (VPS) | `ROADMAP → Login Methods` |
| F-43 | fix | P3 | S | | deferred batch: `login_hint`/`max_age`/`ui_locales`, `WWW-Authenticate` on 401, `X-Powered-By` removal — with a future hardening pass | `keycloak-parity/PRD.md` |
| F-46 | feature | P3 | S | wait F-09 (Mailer) | email verification flow — one-time link flips `email_verified`; **blocked until the mail system (Mailer / SMTP) is ready**; admin API + model wiring for the flag already done | `email-verification/PRD.md` |
| F-49 | feature | P2 | S | F-19 | migrate ops auth from api_key to offline token (CI) — end-state JWT only (SSO+offline); F-48 (dual-mode middleware) already landed, static fallback still gated by `[admin] allow_all = true` | `admin-auth/PRD.md #03` |
| F-15 | feature | P3 | L | | social login (Google/GitHub/GitLab) | `ROADMAP → Login Methods` |
| F-16 | feature | P3 | L | | 2FA/TOTP | `ROADMAP → Login Methods` |
| F-17 | feature | P3 | L | | Google-style modal widget (SAM iframe) | `ROADMAP → Login Form` |
| R-08 | refactor | P3 | S | | remaining domain enums (`ResponseMode`) | `ROADMAP → PHP 8` |
| R-13 | refactor | P3 | S | | PSR12 for `tests/` (ROADMAP "PSR12 compliance throughout" was never queued) — 198 auto-fixable violations in 25 files; run phpcbf then widen `composer cs_check` scope | `ROADMAP → PHP 8` |
| R-14 | refactor | P3 | S–M | best alongside F-08/F-09/F-39 (login-lifecycle work) | `Login` model: raw setters → intention-revealing transition methods (`markAuthenticated/markActive/markRefreshed/markExpired`), single serialization home; invariants over metric (S1448 stays, dismiss) | `login-split/PRD.md` |
| R-15 | refactor | P2 | M | | extract application services from 6 fat admin controllers (Clients, Users, Realms, Roles, ScopeRoles, Oidc); single-pass refactor to make all controllers lean adapters | `admin-controller-refactor/PRD.md` |
| R-09 | refactor | P3 | M | | readonly props + constructor promotion | `ROADMAP → PHP 8` |
| R-10 | refactor | P3 | M | | named args + match expressions | `ROADMAP → PHP 8` |
| R-11 | refactor | P3 | L | | PHPStan 5→6→7→8→9 | `ROADMAP → PHPStan` |



**Blocked-by:** empty = pickable now; a task ID = wait for that task first.
Conscious postponements (delayed/deferred) are flagged in Why-now, not as a
status.

## Done handling

Done rows are deleted from the queue; the linked detail docs stay in their feature dirs and git history retains everything. Archive zips are unnecessary — revisit only if `.scratch/` grows unwieldy.
