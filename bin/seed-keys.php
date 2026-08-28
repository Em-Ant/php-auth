#!/usr/bin/env php
<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use AuthServer\Services\Database;
use AuthServer\Services\TokenService;

$dbPath = __DIR__ . '/../db/data.db';
$keysRoot = __DIR__ . '/../keys';

if (!is_dir($keysRoot)) {
    mkdir($keysRoot, 0777, true);
}

$pdo = Database::connect("sqlite:{$dbPath}");
$kids = $pdo->query('SELECT DISTINCT keys_id FROM realms')->fetchAll(\PDO::FETCH_COLUMN);

foreach ($kids as $kid) {
    $dir = $keysRoot . '/' . $kid;
    if (is_dir($dir)) {
        echo "$keysRoot/$kid present\n";
        continue;
    }
    TokenService::createKeys(kid: $kid, keysRoot: $keysRoot);
    echo "generated $keysRoot/$kid\n";
}
