<?php

// Upload this file to Altervista and visit https://your-site.altervista.org/check-ip.php
// It will show you which IP headers are available and what values they carry.

$headers = [
    'REMOTE_ADDR',
    'HTTP_X_FORWARDED_FOR',
    'HTTP_X_REAL_IP',
    'HTTP_CLIENT_IP',
    'HTTP_X_FORWARDED',
    'HTTP_FORWARDED_FOR',
    'HTTP_FORWARDED',
    'HTTP_CF_CONNECTING_IP',
];

echo "<h1>IP Header Check</h1>";
echo "<table border='1' cellpadding='8' cellspacing='0'>";
echo "<tr><th>Header</th><th>Value</th></tr>";

foreach ($headers as $h) {
    $val = $_SERVER[$h] ?? '<em>not set</em>';
    echo "<tr><td><code>{$h}</code></td><td><code>{$val}</code></td></tr>";
}

echo "</table>";

echo "<h2>All \$_SERVER keys (relevant)</h2>";
echo "<pre>";
foreach ($_SERVER as $key => $val) {
    if (str_contains($key, 'IP') || str_contains($key, 'ADDR') || str_contains($key, 'FORWARD') || str_contains($key, 'PROXY') || str_contains($key, 'REMOTE')) {
        echo htmlspecialchars("{$key} => {$val}") . "\n";
    }
}
echo "</pre>";
