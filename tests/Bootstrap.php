<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

$keysDir = __DIR__ . '/../keys';

if (!is_dir($keysDir)) {
    mkdir($keysDir, 0755, true);
}

$kids = [
    '33ce4036-0a36-45b9-ba74-6087d03c3b35',
    '2daca932-9ae0-411b-9bec-d8dac4cbe70b',
];

foreach ($kids as $kid) {
    $dir = "$keysDir/$kid";
    if (is_dir($dir)) {
        continue;
    }
    mkdir($dir, 0755, true);

    $config = [
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ];

    $dn = [
        'countryName'            => 'IT',
        'stateOrProvinceName'    => 'TR',
        'localityName'           => 'Terni',
        'organizationName'       => 'localhost',
        'organizationalUnitName' => 'auth',
        'commonName'             => 'auth_server',
        'emailAddress'           => 'test@example.com',
    ];

    $keyPair = openssl_pkey_new($config);
    $csr = openssl_csr_new($dn, $keyPair, $config);

    /** @disregard */
    $cert = openssl_csr_sign($csr, null, $keyPair, 365, $config, 0);

    openssl_x509_export($cert, $x509);
    openssl_pkey_export($keyPair, $privateKeyPem);

    $details = openssl_pkey_get_details($keyPair);
    $publicKeyPem = $details['key'];

    file_put_contents("$dir/public_key.pem", $publicKeyPem);
    file_put_contents("$dir/private_key.pem", $privateKeyPem);
    file_put_contents("$dir/cert.pem", $x509);

    $keys = [
        'keys' => [
            [
                'kid' => $kid,
                'kty' => 'RSA',
                'alg' => 'RS256',
                'use' => 'sig',
                'n' => rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '='),
                'e' => rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '='),
                'x5c' => [
                    str_replace(["\r\n", "\n", '-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----'], '', $x509),
                ],
                'x5t' => rtrim(strtr(base64_encode(openssl_x509_fingerprint($cert)), '+/', '-_'), '='),
                'x5t#sha256' => rtrim(strtr(base64_encode(openssl_x509_fingerprint($cert, 'sha256')), '+/', '-_'), '='),
            ],
        ],
    ];

    file_put_contents("$dir/keys.json", json_encode($keys, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}
