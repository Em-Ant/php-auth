# Merge E2E scripts into one configurable script

status: **DEFERRED** — filed for later; not implemented.
Superseded by backlog item **F-20** (`.scratch/ci-e2e/PRD.md`), which covers
the script split/merge with a fuller contract.

## Current state (as of 08/01/2026)

Two scripts with overlapping logic:

| Script | Target | Boots server | Extra checks vs the other |
|---|---|---|---|
| `bin/e2e-test.sh` | `http://localhost:8000` | yes (PHP dev server + `/health`) | — |
| `bin/e2e-test-keycloak.sh` | `BASE_URL` env (production) | no | OIDC discovery, `/certs`, `/userinfo`, 3p-cookies + login-status-iframe |

Both now cover: auth → login → token → introspect (access/refresh/id) →
bad-client 401 → garbage token → refresh + rotation → revoke refresh → revoke
access → introspect revoked → client_credentials.

## Differences to reconcile

1. **Server bootstrap**: local script starts `php -S ... router.php` and waits
   on `/health`. Remote script assumes a running server.
2. **Discovery/certs/userinfo/3p-cookies checks**: only in the keycloak script.
3. **Step numbering**: already drifted (12 vs 11 steps, with `=== Step N ===`
   headers mismatching actual order in the keycloak script).
4. **Hardcoded params**: local script hardcodes `kc_app`/`test`/
   `https://www.keycloak.org/app`; keycloak script exposes `CLIENT`, `REALM`,
   `REDIRECT_URI`, `BASE_URL` via env. `EMAIL`/`PASSWORD`/`CLIENT_SECRET` are
   not configurable in either.

## Proposal

Single canonical script (e.g. `bin/e2e-test.sh`) configured purely by env:

```
BASE_URL        target base URL            (default http://localhost:8000)
REALM           realm name                 (default test)
CLIENT          client name                (default kc_app)
REDIRECT_URI                               (default https://www.keycloak.org/app)
EMAIL / PASSWORD                            (default test@example.com / tst)
CLIENT_SECRET   optional, appended when set (client_credentials/confidential clients)
START_SERVER    1 = boot local dev server + health-check (default 1)
                0 = assume server already running (pipeline usage)
```

- Keep all features (union of both scripts) in one ordered step list.
- Delete `bin/e2e-test-keycloak.sh`; remove the `test:e2e:kc` composer script.
- Update `.github/workflows/deploy.yml` e2e job:
  `bash bin/e2e-test.sh` with env `BASE_URL: ${{ secrets.APP_URL }}`,
  `START_SERVER: 0`, `REALM: test`, `CLIENT: kc_app`,
  `REDIRECT_URI: https://www.keycloak.org/app`.
- Update `AGENTS.md` / `README.md` e2e docs to mention remote mode.

## Risks

- Pipeline currently passes `CLIENT` as `kc_app`, which is public
  (`require_auth=false`) in production seed — client_credentials needs no
  secret. If a confidential client is ever used, `CLIENT_SECRET` must be
  supplied or the step will 400.
- Health check should stay optional (non-fatal) in `START_SERVER=0` mode in
  case `/health` is not exposed on the deploy target.

## References

- `bin/e2e-test.sh`
- `bin/e2e-test-keycloak.sh`
- `.github/workflows/deploy.yml` (e2e job)
