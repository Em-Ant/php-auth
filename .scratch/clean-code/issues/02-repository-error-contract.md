# Repository error contract

**Severity:** medium — infrastructure failures are masked as missing data.

Every repository method catches `\PDOException`, logs the message, returns `null` (e.g. `LoginRepository::findById`, `SessionRepository::create`). A DB outage becomes "not found", which callers translate into `ValidationFailed('invalid client id')`-style 400s — wrong status, wrong semantics, and the real error is only in the log.

**Fix:** rethrow a dedicated exception (e.g. `StorageFailed` or a `StorageException`) on genuine failures; return `null` only for empty result sets. Audit callers so the exception maps to 500.
