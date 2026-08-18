# TokenService::createKeys handles no boundary failures

**Severity:** medium — unchecked crypto/filesystem I/O surfaces late as runtime failures.

`TokenService::createKeys()` (`Services/TokenService.php:103`) calls `openssl_pkey_new`, `openssl_csr_sign`, `mkdir`, and `file_put_contents` without checking their return values. A failed key generation or write yields a `null`/empty file, and `FilesystemKeyStore::findKeys()` only throws when the file is missing at request time — a null private key would then fail token signing, far from the error's origin.

**Fix:** check each openssl/file call and throw an explicit exception (e.g. `StorageFailed` or a dedicated `KeysFailed`) with context; fail fast at `POST /admin/keys` instead of at signing time. Consider a learning test against a read-only keys dir.