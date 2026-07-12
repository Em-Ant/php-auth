# Redirect URI value object

**Status: Done**

**PRD:** Architecture Deepening
**Priority:** Low

## Problem

`getRedirectUri()` and `getLoginRequiredRedirectUri()` in `Authorize` controller share identical logic for appending query vs fragment parameters to a redirect URI, including existing-fragment handling. Duplicated, untested, in the HTTP handler.

## Solution

Replace with a `RedirectUri` value object.

## Created files

- `src/Models/RedirectUri.php`

## Modified files

- `src/Controllers/Authorize.php` — replace both redirect methods with `RedirectUri`, remove duplicated code
