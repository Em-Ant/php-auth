<?php

declare(strict_types=1);

namespace AuthServer;

use AuthServer\App\AppBuilder;
use AuthServer\Config\Definitions;
use DI\Bridge\Slim\Bridge;

if (function_exists('opcache_invalidate') && filter_var(ini_get('opcache.enable'), FILTER_VALIDATE_BOOLEAN)) {
    opcache_invalidate(__FILE__, true);
}

require_once __DIR__ . '/../vendor/autoload.php';

$containerObj = new \DI\Container(Definitions::get());

$app = AppBuilder::create($containerObj, rateLimiting: true);

$app->run();
