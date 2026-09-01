<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\StorageFailed;

use function AuthServer\getGuid;

/**
 * Generates RSA key pairs (private key + certificate + JWKS) and writes them
 * to the filesystem under `keys/<kid>/`. Used by the admin Keys endpoint and
 * the `bin/seed-keys` CLI script.
 */
class KeyProvisioning
{
    public function __construct(
        private readonly string $keysRoot,
    ) {
    }

    public function createKeys(
        ?string $kid = null,
        ?array $dn = [],
        ?int $certDuration = 365,
    ): string {
        $config = array(
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );

        $dn = array_merge(array(
            "countryName"               => "IT",
            "stateOrProvinceName"       => "TR",
            "localityName"              => "Terni",
            "organizationName"          => "localhost",
            "organizationalUnitName"    => "auth",
            "commonName"                => "auth_server",
            "emailAddress"              => "test@example.com"
        ), $dn);

        $newKeyPair = openssl_pkey_new($config);
        if ($newKeyPair === false) {
            throw new StorageFailed('failed to generate RSA key pair');
        }

        $csr = openssl_csr_new($dn, $newKeyPair, $config);
        if ($csr === false) {
            throw new StorageFailed('failed to create CSR');
        }

        $cert = openssl_csr_sign(
            $csr,
            null,
            $newKeyPair,
            $certDuration,
            $config,
            0
        );
        if ($cert === false) {
            throw new StorageFailed('failed to sign certificate');
        }

        if (!openssl_x509_export($cert, $x509)) {
            throw new StorageFailed('failed to export certificate');
        }
        if (!openssl_pkey_export($newKeyPair, $privateKeyPem)) {
            throw new StorageFailed('failed to export private key');
        }

        $details = openssl_pkey_get_details($newKeyPair);
        if ($details === false || !isset($details['key'], $details['rsa']['n'], $details['rsa']['e'])) {
            throw new StorageFailed('failed to extract key details');
        }
        $kid = $kid ?? getGuid();
        $keys = [
            "keys" => [
                [
                    "kid" => $kid,
                    "kty" => "RSA",
                    "alg" => "RS256",
                    "use" => "sig",
                    "n" => Base64Utils::b64UrlEncode($details['rsa']['n']),
                    "e" => Base64Utils::b64UrlEncode($details['rsa']['e']),
                    "x5c" => [
                        self::removeBeginEnd($x509)
                    ],
                    "x5t" => Base64Utils::b64UrlEncode(openssl_x509_fingerprint($x509)),
                    "x5t#sha256" => Base64Utils::b64UrlEncode(openssl_x509_fingerprint($x509, 'sha256')),
                ]
            ]
        ];

        $dir = $this->keysRoot . "/$kid";
        if (!@mkdir($dir) && !is_dir($dir)) {
            throw new StorageFailed("failed to create keys directory $dir");
        }

        $files = [
            'public_key.pem' => $details['key'],
            'private_key.pem' => $privateKeyPem,
            'cert.pem' => $x509,
            'keys.json' => json_encode($keys, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
        ];
        foreach ($files as $name => $content) {
            if (file_put_contents("$dir/$name", $content) === false) {
                throw new StorageFailed("failed to write $name for keys $kid");
            }
        }

        return $kid;
    }

    private static function removeBeginEnd(string $pem): string
    {
        $pem = preg_replace("/-----BEGIN (.*)-----/", "", $pem);
        $pem = preg_replace("/-----END (.*)-----/", "", $pem);
        $pem = str_replace("\r\n", "", $pem);
        $pem = str_replace("\n", "", $pem);
        return trim($pem);
    }
}
