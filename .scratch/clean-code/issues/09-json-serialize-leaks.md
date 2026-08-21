# Model jsonSerialize leaks sensitive fields

status: **DONE** (2026-08-21) — all six models (`User`, `Login`, `Client`, `Session`, `Realm`, `OfflineSession`) now serialize via explicit whitelist maps; `get_object_vars` removed everywhere. Excluded: `User::$password`, `Client::$client_secret`, `Login::$code`/`$code_challenge`/`$csrf_token`/`$refresh_token`, `OfflineSession::$refresh_token`/`$nonce`. Admin `toArray()` maps untouched (their shapes differ, e.g. `has_secret`). Covered by `tests/Unit/Models/JsonSerializeTest.php` (6 tests). BACKLOG F-35 closed.

**Severity:** high — live footgun: a single direct serialization returns the password hash.

Every model `jsonSerialize()` uses `get_object_vars($this)` (`Models/User.php:77`, `Models/Login.php:169`, plus `Session`, `Realm`, `Client`), which serializes **all** private properties — including `User::$password` (the Argon2id hash), `Login::$refresh_token`, `Login::$csrf_token`, and `Login::$code`.

Admin flows currently call explicit `toArray()` maps, so nothing leaks today. But a plain `JsonResponse::create($response, $user)` anywhere would return the password hash; coupling serialization to private field layout also makes future field additions silently leak.

**Fix:** replace `get_object_vars($this)` with explicit serialization maps per model (like the admin `toArray()` helpers) that whitelist only safe fields; add a test asserting serialized output excludes `password`/`refresh_token`/`csrf_token`/`code`.