<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Interfaces\KeyStore;
use AuthServer\Interfaces\RoleRepository;
use AuthServer\Models\Client;
use AuthServer\Models\Login;
use AuthServer\Models\OfflineSession;
use AuthServer\Models\Realm;
use AuthServer\Models\Session;
use AuthServer\Models\User;

use function AuthServer\get_guid;

class TokenService
{
    private string $issuer;
    private KeyStore $keyStore;
    private RoleRepository $roles;

    public function __construct(
        string $issuer,
        KeyStore $keyStore,
        RoleRepository $roles
    ) {
        $this->issuer = $issuer;
        $this->keyStore = $keyStore;
        $this->roles = $roles;
    }

    public function verifySignature(string $token, Realm $realm): bool
    {
        $kid = $realm->getKeysId();
        $keySet = $this->keyStore->findKeys($kid);
        $public_key = $keySet->publicKey;

        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return false;
        }

        $header = json_decode(Base64Utils::b64UrlDecode($parts[0]), true);
        if (!is_array($header) || ($header['alg'] ?? null) !== 'RS256') {
            return false;
        }

        $data = "$parts[0].$parts[1]";
        $signature = Base64Utils::b64UrlDecode($parts[2]);

        $result = openssl_verify(
            $data,
            $signature,
            $public_key,
            "sha256WithRSAEncryption"
        );

        return $result === 1;
    }

    public function createToken(array $payload, string $keys_id): string
    {
        $keySet = $this->keyStore->findKeys($keys_id);
        $private_key = $keySet->privateKey;

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
        return $this->decodeTokenSafely($token) ?? [];
    }

    public function decodeTokenSafely(string $token): ?array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }

        $payload = json_decode(Base64Utils::b64UrlDecode($parts[1]), true);

        return is_array($payload) ? $payload : null;
    }



    public static function createKeys(
        ?string $kid = null,
        ?array $dn = [],
        ?int $cert_duration = 365,
        string $keysRoot = 'keys'
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
        $kid = $kid ?? get_guid();
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

        $dir = "$keysRoot/$kid";
        mkdir($dir);

        file_put_contents("$dir/public_key.pem", $public_key_pem);
        file_put_contents("$dir/private_key.pem", $private_key_pem);
        file_put_contents("$dir/cert.pem", $x509);
        file_put_contents("$dir/keys.json", json_encode($keys, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        return $kid;
    }

    public function createClientCredentialsToken(
        Realm $realm,
        Client $client,
        string $scope
    ): array {
        $now = time();
        $kid = $realm->getKeysId();

        $access_token = $this->createToken(
            [
                "exp" => $now + $realm->getAccessTokenExpiresIn(),
                "iat" => $now,
                "jti" => get_guid(),
                "iss" => $this->issuer . "/realms/" . $realm->getName(),
                "aud" => $client->getName(),
                "sub" => $client->getName(),
                "typ" => "Bearer",
                "azp" => $client->getName(),
                "allowed-origins" => [
                    $client->getUri()
                ],
                "client_id" => $client->getName(),
                "scope" => $scope,
            ],
            $kid
        );

        return [
            "access_token" => $access_token,
            "expires_in" => $realm->getAccessTokenExpiresIn(),
            "token_type" => "Bearer",
            "scope" => $scope,
            "not-before-policy" => 0,
        ];
    }

    /**
     * Offline token bundle: the refresh token carries `typ: Offline` and the
     * realm-configured offline TTL, and the session claims (sid, acr,
     * auth_time) come from the offline session — which survives SSO logout.
     */
    public function createOfflineTokenBundle(
        Realm $realm,
        OfflineSession $offlineSession,
        Client $client,
        User $user
    ): array {
        $now = time();
        $context = [
            'subject' => $offlineSession->getUserId(),
            'auth_time' => $offlineSession->getAuthenticatedAt() !== null
                ? date_timestamp_get($offlineSession->getAuthenticatedAt())
                : $now,
            'acr' => $offlineSession->getAcr(),
            'sid' => $offlineSession->getId(),
            'nonce' => $offlineSession->getNonce(),
            'scope' => $offlineSession->getScope(),
        ];

        return $this->createTokenBundleFromContext(
            $realm,
            $context,
            $client,
            $user,
            $realm->getOfflineRefreshTokenExpiresIn(),
            'Offline'
        );
    }

    public function createTokenBundle(
        Realm $realm,
        Session $session,
        Login $login,
        Client $client,
        User $user
    ): array {
        $context = [
            'subject' => $session->getUserId(),
            'auth_time' => date_timestamp_get($login->getAuthenticatedAt()),
            'acr' => $session->getAcr(),
            'sid' => $session->getId(),
            'nonce' => $login->getNonce(),
            'scope' => $login->getScope(),
        ];

        return $this->createTokenBundleFromContext(
            $realm,
            $context,
            $client,
            $user,
            $realm->getRefreshTokenExpiresIn(),
            'Refresh'
        );
    }

    /**
     * Assembles the access/id/refresh triple from a shared grant context.
     *
     * @param array{
     *     subject: string,
     *     auth_time: int,
     *     acr: string,
     *     sid: string,
     *     nonce: string|null,
     *     scope: string
     * } $context
     */
    private function createTokenBundleFromContext(
        Realm $realm,
        array $context,
        Client $client,
        User $user,
        int $refreshExpiresIn,
        string $refreshTyp
    ): array {
        $now = time();
        $kid = $realm->getKeysId();

        // Role claims are read once per issuance, straight from the roles
        // tables — the User model carries no authorization state.
        $roleClaims = [
            'realm' => $this->roles->findRealmRoleNamesByUserId(
                $user->getId(),
                $user->getRealmId()
            ),
            'resource' => $this->resourceAccessClaim($user, $client),
        ];

        $access_token = $this->createAccessToken(
            $now,
            $realm->getAccessTokenExpiresIn(),
            $realm->getName(),
            $context,
            $client,
            $user,
            $roleClaims,
            $kid
        );
        $id_token = $this->createIdToken(
            $now,
            $realm->getAccessTokenExpiresIn(),
            $realm->getName(),
            $context,
            $client,
            $user,
            $access_token,
            $kid
        );
        $refresh_token = $this->createRefreshToken(
            $now,
            $refreshExpiresIn,
            $realm->getName(),
            $context,
            $client,
            $user,
            $roleClaims,
            $kid,
            $refreshTyp
        );

        return [
            "access_token" => $access_token,
            "expires_in" => $realm->getAccessTokenExpiresIn(),
            "refresh_expires_in" => $refreshExpiresIn,
            "refresh_token" => $refresh_token,
            "token_type" => "Bearer",
            "id_token" => $id_token,
            "not-before-policy" => 0,
            "session_state" => $context['sid'],
            "scope" => $context['scope'],
        ];
    }

    /**
     * Role claims shared across the bundle's tokens.
     *
     * @param array{realm: list<string>, resource: array<string, array<string, list<string>>>|null} $roleClaims
     */
    private function createRefreshToken(
        int $now,
        int $validity,
        string $realm_name,
        array $context,
        Client $client,
        User $user,
        array $roleClaims,
        string $keys_id,
        string $typ = 'Refresh'
    ): string {
        $exp = $now + $validity;
        $claims = [
            "exp" => $exp,
            "iat" => $now,
            "jti" => get_guid(),
            "iss" => $this->issuer . "/realms/$realm_name",
            "aud" => $this->issuer,
            "sub" => $context['subject'],
            "typ" => $typ,
            "azp" => $client->getName(),
            "nonce" => $context['nonce'],
            "session_state" => $context['sid'],
            "realm_access" => [
                "roles" => $roleClaims['realm']
            ],
            "scope" => $context['scope'],
            "sid" => $context['sid']
        ];
        if ($roleClaims['resource'] !== null) {
            $claims["resource_access"] = $roleClaims['resource'];
        }
        return $this->createToken($claims, $keys_id);
    }

    /**
     * @param array{
     *     subject: string,
     *     auth_time: int,
     *     acr: string,
     *     sid: string,
     *     nonce: string|null,
     *     scope: string
     * } $context
     * @param array{realm: list<string>, resource: array<string, array<string, list<string>>>|null} $roleClaims
     */
    private function createAccessToken(
        int $now,
        int $validity,
        string $realm_name,
        array $context,
        Client $client,
        User $user,
        array $roleClaims,
        string $keys_id
    ): string {
        $exp = $now + $validity;
        $claims = [
            "exp" => $exp,
            "iat" => $now,
            "auth_time" => $context['auth_time'],
            "jti" => get_guid(),
            "iss" => $this->issuer . "/realms/$realm_name",
            "aud" => $client->getName(),
            "sub" => $context['subject'],
            "typ" => "Bearer",
            "azp" => $client->getName(),
            "nonce" => $context['nonce'],
            "session_state" => $context['sid'],
            "acr" => $context['acr'],
            "allowed-origins" => [
                $client->getUri()
            ],
            "realm_access" => [
                "roles" => $roleClaims['realm']
            ],
            "scope" => $context['scope'],
            "sid" => $context['sid'],
            "preferred_username" => $user->getName()
        ];
        if ($roleClaims['resource'] !== null) {
            $claims["resource_access"] = $roleClaims['resource'];
        }
        return $this->createToken($claims, $keys_id);
    }

    /**
     * @param array{
     *     subject: string,
     *     auth_time: int,
     *     acr: string,
     *     sid: string,
     *     nonce: string|null,
     *     scope: string
     * } $context
     */
    private function createIdToken(
        int $now,
        int $validity,
        string $realm_name,
        array $context,
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
                "auth_time" => $context['auth_time'],
                "jti" => get_guid(),
                "iss" => $this->issuer . "/realms/$realm_name",
                "aud" => $client->getName(),
                "sub" => $context['subject'],
                "typ" => "ID",
                "azp" => $client->getName(),
                "nonce" => $context['nonce'],
                "session_state" => $context['sid'],
                "at_hash" => self::calculateAtHash($access_token),
                "acr" => $context['acr'],
                "sid" => $context['sid'],
                "preferred_username" => $user->getName()
            ],
            $keys_id
        );
    }

    /**
     * `resource_access.<client>.roles` for the client the token is issued to,
     * omitted when the user holds no roles for it.
     *
     * @return array<string, array<string, list<string>>>|null
     */
    private function resourceAccessClaim(User $user, Client $client): ?array
    {
        $clientRoles = $this->roles->findClientRoleNamesByUserId(
            $user->getId(),
            $user->getRealmId()
        );
        $roles = $clientRoles[$client->getName()] ?? [];
        if ($roles === []) {
            return null;
        }
        return [$client->getName() => ['roles' => $roles]];
    }

    private static function calculateAtHash(string $accessToken): string
    {
        $hash = hash('sha256', $accessToken, true);

        return Base64Utils::b64UrlEncode(substr($hash, 0, (int)(strlen($hash) / 2)));
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
