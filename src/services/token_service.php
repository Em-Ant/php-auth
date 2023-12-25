<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Models\Session;
use AuthServer\Models\Client;
use AuthServer\Models\User;
use Emant\BrowniePhp\Utils;
use AuthServer\Models\Login;
use AuthServer\Models\Realm;
use AuthServer\Services\Base64Utils;

class TokenService
{
    private string $issuer;

    public function __construct(
        string $issuer
    ) {
        $this->issuer = $issuer;
    }

    public function validateToken(string $token, Realm $realm): int
    {

        $kid = $realm->getKeysId();
        $public_key = file_get_contents("keys/$kid/public_key.pem");

        if (!$public_key) {
            throw new \RuntimeException('keys not found');
        }

        $t = explode('.', $token);
        $header = json_decode(Base64Utils::b64UrlDecode($t[0]), true);

        if ($header['alg'] != 'RS256') {
            return 0;
        }

        $data = "$t[0].$t[1]";
        $signature = Base64Utils::b64UrlDecode($t[2]);

        return openssl_verify(
            $data,
            $signature,
            $public_key,
            "sha256WithRSAEncryption"
        );
    }

    public function tokenIsExpired(string $token): bool
    {
        $decoded = $this->decodeTokenPayload($token);
        return $decoded['exp'] < time();
    }

    public function createToken(array $payload, $keys_id): string
    {
        $private_key = file_get_contents("keys/$keys_id/private_key.pem");

        if (!$private_key) {
            throw new \RuntimeException('keys not found');
        }

        $header = json_encode([
            'typ' => 'JWT',
            'alg' => 'RS256',
            'kid' => $keys_id
        ]);

        $base64UrlHeader = Base64Utils::b64UrlEncode($header);
        $base64UrlPayload = Base64Utils::b64UrlEncode(json_encode($payload));

        openssl_sign(
            $base64UrlHeader . "." . $base64UrlPayload,
            $signature,
            $private_key,
            'sha256WithRSAEncryption'
        );

        $base64UrlSignature = Base64Utils::b64UrlEncode($signature);
        return $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;
    }

    public function decodeTokenPayload(string $token): array
    {
        $t = explode('.', $token);
        return json_decode(Base64Utils::b64UrlDecode($t[1]), true);
    }



    public static function createKeys(
        ?string $kid = null,
        ?array $dn = [],
        ?int $cert_duration = 365
    ): void {
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

        $new_key_pair = openssl_pkey_new($config);

        $csr = openssl_csr_new($dn, $new_key_pair, $config);
        $cert = openssl_csr_sign(
            $csr,
            null,
            $new_key_pair,
            $cert_duration,
            $config,
            0
        );

        openssl_x509_export($cert, $x509);
        openssl_pkey_export($new_key_pair, $private_key_pem);

        $details = openssl_pkey_get_details($new_key_pair);
        $public_key_pem = $details['key'];
        $kid = $kid ?? Utils::get_guid();
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

        $dir = "keys/$kid";
        mkdir($dir);

        file_put_contents("$dir/public_key.pem", $public_key_pem);
        file_put_contents("$dir/private_key.pem", $private_key_pem);
        file_put_contents("$dir/cert.pem", $x509);
        file_put_contents("$dir/keys.json", json_encode($keys, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }

    public function createTokenBundle(
        Realm $realm,
        Session $session,
        Login $login,
        Client $client,
        User $user
    ): array {
        $now = time();
        $kid = $realm->getKeysId();
        $access_token = $this->createAccessToken(
            $now,
            $realm->getAccessTokenExpiresIn(),
            $realm->getName(),
            $login,
            $session,
            $client,
            $user,
            $kid
        );
        $id_token = $this->createIdToken(
            $now,
            $realm->getAccessTokenExpiresIn(),
            $realm->getName(),
            $login,
            $session,
            $client,
            $user,
            $access_token,
            $kid
        );
        $refresh_token = $this->createRefreshToken(
            $now,
            $realm->getRefreshTokenExpiresIn(),
            $realm->getName(),
            $login,
            $session,
            $client,
            $user,
            $kid
        );

        return [
            "access_token" => $access_token,
            "expires_in" => $realm->getAccessTokenExpiresIn(),
            "refresh_expires_in" => $realm->getRefreshTokenExpiresIn(),
            "refresh_token" => $refresh_token,
            "token_type" => "Bearer",
            "id_token" => $id_token,
            "not-before-policy" => 0,
            "session_state" => $session->getId(),
            "scope" => $login->getScope(),
        ];
    }

    private function createRefreshToken(
        int $now,
        int $validity,
        $realm_name,
        Login $login,
        Session $session,
        Client $client,
        User $user,
        string $keys_id
    ): string {
        $exp = $now + $validity;
        return $this->createToken(
            [
                "exp" => $exp,
                "iat" => $now,
                "jti" => Utils::get_guid(),
                "iss" => $this->issuer . "/realms/$realm_name",
                "aud" => $this->issuer,
                "sub" => $session->getUserId(),
                "typ" => "Refresh",
                "azp" => $client->getName(),
                "nonce" => $login->getNonce(),
                "session_state" => $session->getId(),
                "realm_access" => [
                    "roles" => $user->getRealmRoles()
                ],
                "scope" => $login->getScope(),
                "sid" => $session->getId()
            ],
            $keys_id
        );
    }

    private function createAccessToken(
        int $now,
        int $validity,
        string $realm_name,
        Login $login,
        Session $session,
        Client $client,
        User $user,
        string $keys_id
    ): string {
        $exp = $now + $validity;
        return $this->createToken(
            [
                "exp" => $exp,
                "iat" => $now,
                "auth_time" => date_timestamp_get($login->getAuthenticatedAt()),
                "jti" => Utils::get_guid(),
                "iss" => $this->issuer,
                "aud" => $client->getName(),
                "sub" => $session->getUserId(),
                "typ" => "Bearer",
                "azp" => $client->getName(),
                "nonce" => $login->getNonce(),
                "session_state" => $session->getId(),
                "acr" => $session->getAcr(),
                "allowed-origins" => [
                    $client->getUri()
                ],
                "realm_access" => [
                    "roles" => $user->getRealmRoles()
                ],
                "scope" => $login->getScope(),
                "sid" => $session->getId(),
                "preferred_username" => $user->getName()
            ],
            $keys_id
        );
    }

    private function createIdToken(
        int $now,
        int $validity,
        string $realm_name,
        Login $login,
        Session $session,
        Client $client,
        User $user,
        string $access_token,
        string $keys_id
    ): string {
        $exp = $now + $validity;
        return $this->createToken(
            [
                "exp" => $exp,
                "iat" => $now,
                "auth_time" => date_timestamp_get($login->getAuthenticatedAt()),
                "jti" => Utils::get_guid(),
                "iss" => $this->issuer . "/realms/$realm_name",
                "aud" => $client->getName(),
                "sub" => $session->getUserId(),
                "typ" => "ID",
                "azp" => $client->getName(),
                "nonce" => $login->getNonce(),
                "session_state" => $session->getId(),
                "at_hash" => md5($access_token),
                "acr" => $session->getAcr(),
                "sid" => $session->getId(),
                "preferred_username" => $user->getName()
            ],
            $keys_id
        );
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
