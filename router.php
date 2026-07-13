<?php

declare(strict_types=1);

if (php_sapi_name() === 'cli-server') {
    $publicPath = __DIR__ . '/public' . parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    if (is_file($publicPath)) {
        return false;
    }
}

chdir(__DIR__);
require __DIR__ . '/public/index.php';
