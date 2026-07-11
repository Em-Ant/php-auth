# Redirect URI value object

**PRD:** Architecture Deepening
**Priority:** Low

## Problem

`getRedirectUri()` and `getLoginRequiredRedirectUri()` in `Authorize` controller share identical logic for appending query vs fragment parameters to a redirect URI, including existing-fragment handling. Duplicated, untested, in the HTTP handler.

## Solution

Replace with a `RedirectUri` value object.

## Interface sketch

```php
class RedirectUri {
    public function __construct(
        private string $baseUri,
        private string $responseMode, // 'query' | 'fragment'
    );

    public function withParam(string $key, string $value): self;
    public function __toString(): string;
}
```

## Files

`src/controllers/authorize.php`, new file in `src/models/` or `src/services/`
