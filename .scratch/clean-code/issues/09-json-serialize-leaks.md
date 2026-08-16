# Model jsonSerialize leaks sensitive fields

**Severity:** high — live footgun: a single direct serialization returns the password hash.

Every model `jsonSerialize()` uses `get_object_vars($this)` (`Models/User.php:77`, `Models/Login.php:169`, plus `Session`, `Realm`, `Client`), which serializes **all** private properties — including `User::$password` (the Argon2id hash), `Login::$refresh_token`, `Login::$csrf_token`, and `Login::$code`.

Admin flows currently call explicit `toArray()` maps, so nothing leaks today. But a plain `JsonResponse::create($response, $user)` anywhere would return the password hash; coupling serialization to private field layout also makes future field additions silently leak.

**Fix:** replace `get_object_vars($this)` with explicit serialization maps per model (like the admin `toArray()` helpers) that whitelist only safe fields; add a test asserting serialized output excludes `password`/`refresh_token`/`csrf_token`/`code`.