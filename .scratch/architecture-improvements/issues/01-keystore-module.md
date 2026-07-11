# KeyStore module

**PRD:** Architecture Deepening
**Priority:** High

## Problem

Key loading is four raw `file_get_contents()` calls across `TokenService::validateToken()`, `TokenService::createToken()`, `TokenService::createKeys()`, and `Authorize::sendKeys()`. No seam. Token tests require keys on disk.

## Solution

Introduce a `KeyStore` interface with `findKeys(kid): KeySet`. `FilesystemKeyStore` reads from `keys/<kid>/`; `InMemoryKeyStore` accepts keys in constructor for tests. Inject into `TokenService` and `Authorize` controller.

## Interface sketch

```php
interface KeyStore {
    public function findKeys(string $kid): KeySet;
}

class KeySet {
    public function __construct(
        public readonly string $publicKey,
        public readonly string $privateKey,
        public readonly string $cert,
        public readonly array $jwks,
    );
}
```

## Files

`src/services/token_service.php`, `src/controllers/authorize.php`, `index.php`, new files in `src/services/`
