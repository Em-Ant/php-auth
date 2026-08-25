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
| A-03 | fix | P1 | M | | admin list endpoints unbounded — pagination + `{items,total,limit,offset}` envelope (users/clients/sessions/logins); auth paths unaffected, API has no consumers yet | `admin-api/issues/03-…` |
| F-05 | feature | P1 | L | | scope↔role gating at issuance (`roles` tables shipped in F-04) | `scopes/issues/03-…` |
| F-07 | feature | P2 | M | | audit log table + query | `ROADMAP → Admin API` |
| F-08 | feature | P2 | S | | ROPC grant | `ROADMAP → Login Methods` |
| F-09 | feature | P2 | M | | email magic link | `ROADMAP → Login Methods` |
| F-10 | feature | P2 | M | | consent screen (`offline_access`) — delayed by design; client gating (scopes #02) is the control until then | `ROADMAP → Token Lifecycle` |
| F-11 | feature | P2 | S | | per-realm password policy | `ROADMAP → Admin API` |
| F-12 | feature | P2 | M | | admin config surface for scopes/roles (roles CRUD from F-04; mappings after F-05) | `scopes/issues/04-…` |
| F-13 | feature | P2 | S | | per-realm login page config | `ROADMAP → Login Form` |
| F-19 | feature | P2 | S | | blacklist purge + expired-session cleanup | `token-lifecycle/issues/05-…` |
| F-20 | refactor | P2 | M | | split E2E into two contracts — prod smoke (`bin/smoke-test.sh`, no DB, bounded footprint, ~30 checks) + local OIDC integrity suite; phase 2: PHPUnit-against-live-`BASE_URL` (no Playwright) — also replaces the ad-hoc `python3` JWT payload decoding in `bin/e2e-test.sh` with PHP tooling | `ci-e2e/PRD.md` |
| F-37 | fix | P2 | S | | JWKS `x5t`/`x5t#sha256` = b64url of binary thumbprint (RFC 7517 §4.7; breaks JWKS verification) — verified live vs Keycloak | `keycloak-parity/PRD.md` |
| F-38 | fix | P2 | M | | check-session iframe mechanism: salted `KEYCLOAK_SESSION` cookie + client-side SHA-256 (premise verified live) | `keycloak-parity/PRD.md` |
| F-39 | fix | P2 | S | | sliding idle session timeout — idle leg on `updated_at` | `keycloak-parity/PRD.md` |
| F-40 | fix | P2 | S | | `acr` default `"1"` for password login (verified live) | `keycloak-parity/PRD.md` |
| F-41 | fix | P2 | M | | userinfo claims per scope (`profile`/`email`) | `keycloak-parity/PRD.md` |
| F-42 | fix | P2 | S | | drop `nonce` from access/refresh tokens (ID token only) | `keycloak-parity/PRD.md` |
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
| F-43 | fix | P3 | S | | deferred batch: `login_hint`/`max_age`/`ui_locales`, `WWW-Authenticate` on 401, `X-Powered-By` removal — with a future hardening pass | `keycloak-parity/PRD.md` |

**Blocked-by:** empty = pickable now; a task ID = wait for that task first.
Conscious postponements (delayed/deferred) are flagged in Why-now, not as a
status.

## Done handling

Done rows are deleted from the queue; the linked detail docs stay in their feature dirs and git history retains everything. Archive zips are unnecessary — revisit only if `.scratch/` grows unwieldy.
