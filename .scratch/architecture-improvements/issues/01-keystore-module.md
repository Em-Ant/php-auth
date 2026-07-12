# KeyStore module

**Status: Done**

**PRD:** Architecture Deepening
**Priority:** High

## Problem

Key loading is four raw `file_get_contents()` calls across `TokenService::validateToken()`, `TokenService::createToken()`, `TokenService::createKeys()`, and `Authorize::sendKeys()`. No seam. Token tests require keys on disk.

## Solution

Introduce a `KeyStore` interface with `findKeys(kid): KeySet`. `FilesystemKeyStore` reads from `keys/<kid>/`; `InMemoryKeyStore` accepts keys in constructor for tests. Inject into `TokenService` and `Authorize` controller.

## Created files

- `src/Interfaces/KeyStore.php`
- `src/Models/KeySet.php`
- `src/Services/FilesystemKeyStore.php`

## Modified files

- `src/Services/TokenService.php` — inject KeyStore, replace `file_get_contents()`
- `src/Controllers/Authorize.php` — inject KeyStore, replace `file_get_contents()` in `sendKeys()`
- `index.php` — create `FilesystemKeyStore`, inject into both services
