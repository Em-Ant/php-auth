# TokenService::createKeys handles no boundary failures

**Severity:** medium — unchecked crypto/filesystem I/O surfaces late as runtime failures.

`TokenService::createKeys()` (`Services/TokenService.php:103`) calls `openssl_pkey_new`, `openssl_csr_sign`, `mkdir`, and `file_put_contents` without checking their return values. A failed key generation or write yields a `null`/empty file, and `FilesystemKeyStore::findKeys()` only throws when the file is missing at request time — a null private key would then fail token signing, far from the error's origin.

**Fix:** check each openssl/file call and throw an explicit exception (e.g. `StorageFailed` or a dedicated `KeysFailed`) with context; fail fast at `POST /admin/keys` instead of at signing time. Consider a learning test against a read-only keys dir.

## Comments

### 2026-08-25 — done

Every openssl call (`openssl_pkey_new`, `openssl_csr_new`, `openssl_csr_sign`,
`openssl_x509_export`, `openssl_pkey_export`, `openssl_pkey_get_details`) plus
`mkdir` and all four file writes now checked and throw `StorageFailed` with
context — reuses the existing global error handler (500 JSON), so no new
exception class and no controller change needed. File writes consolidated into
one loop (DRY). Learning tests added to `TokenServiceTest`: happy path writes
all four artifacts into a tmp keys root + JWKS sanity check; unwritable keys
root fails fast (skipped as root). Verified: phpstan clean, PHPCS clean,
PHPUnit 493/493 green, sonar-php scan + dup gate ok (3 pre-existing findings
on untouched lines reported, not fixed). Row removed from BACKLOG queue.

Note for later: the ~97-line same-file duplication the scanner flags inside
`TokenService` (`createAccessToken`/`createRefreshToken`/`createIdToken`
claim arrays) predates this change and is *not* tracked by any backlog row —
candidate issue if it ever gets ranked.