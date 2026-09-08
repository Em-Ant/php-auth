<?php

declare(strict_types=1);

// P-09: never disclose the PHP version. `expose_php` is PHP_INI_SYSTEM in
// some SAPIs, so this is best-effort; the PoweredByHeaderMiddleware strips
// any X-Powered-By header still queued at runtime.
@ini_set('expose_php', '0');
if (function_exists('header_remove')) {
    @header_remove('X-Powered-By');
}
