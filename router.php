<?php

declare(strict_types=1);

if (php_sapi_name() === 'cli-server') {
    $publicPath = __DIR__ . '/public' . parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    $publicPath = realpath($publicPath);
    if ($publicPath !== false && is_file($publicPath) && str_starts_with($publicPath, __DIR__ . '/public')) {
        return false;
    }
}

chdir(__DIR__);
require_once __DIR__ . '/public/index.php';
