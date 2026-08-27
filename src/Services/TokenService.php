<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Interfaces\KeyStore;
use AuthServer\Exceptions\StorageFailed;
use AuthServer\Models\Client;
use AuthServer\Models\GrantContext;
use AuthServer\Models\Login;
use AuthServer\Models\OfflineSession;
use AuthServer\Models\Realm;
use AuthServer\Models\RefreshTokenKind;
use AuthServer\Models\RoleClaims;
use AuthServer\Models\Session;
use AuthServer\Models\User;

use function AuthServer\getGuid;

class TokenService
{
    private string $issuer;
    private KeyStore $keyStore;
    private ScopeResolver $scopeResolver;

    public function __construct(
        string $issuer,
        KeyStore $keyStore,
        ScopeResolver $scopeResolver
    ) {
        $this->issuer = $issuer;
        $this->keyStore = $keyStore;
        $this->scopeResolver = $scopeResolver;
    }

    public function verifySignature(string $token, Realm $realm): bool
    {
        $kid = $realm->getKeysId();
        $keySet = $this->keyStore->findKeys($kid);
        $publicKey = $keySet->publicKey;

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
            $publicKey,
            "sha256WithRSAEncryption"
        );

        return $result === 1;
    }

    public function createToken(array $payload, string $keysId): string
    {
        $keySet = $this->keyStore->findKeys($keysId);
        $privateKey = $keySet->privateKey;

        $header = json_encode([
            'typ' => 'JWT',
            'alg' => 'RS256',
            'kid' => $keysId
        ]);

        $base64UrlHeader = Base64Utils::b64UrlEncode($header);
        $base64UrlPayload = Base64Utils::b64UrlEncode(json_encode($payload));

        $ok = openssl_sign(
            $base64UrlHeader . "." . $base64UrlPayload,
            $signature,
            $privateKey,
            'sha256WithRSAEncryption'
        );
        if (!$ok) {
            throw new StorageFailed('failed to sign JWT');
        }

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
        ?int $certDuration = 365,
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

        $dir = "$keysRoot/$kid";
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

    public function createClientCredentialsToken(
        Realm $realm,
        Client $client,
        string $requestedScope
    ): array {
        $scope = $this->scopeResolver->resolve(
            $requestedScope === '' ? null : $requestedScope,
            $client,
            $realm,
            false
        );

        $now = time();
        $kid = $realm->getKeysId();

        $accessToken = $this->createToken(
            [
                "exp" => $now + $realm->getAccessTokenExpiresIn(),
                "iat" => $now,
                "jti" => getGuid(),
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
            "access_token" => $accessToken,
            "expires_in" => $realm->getAccessTokenExpiresIn(),
            "token_type" => "Bearer",
            "scope" => $scope,
            "not-before-policy" => 0,
        ];
    }

    /**
     * Offline token bundle: the refresh token carries `typ: Offline` and the
     * realm-configured offline TTL.
     *
     * The published `sid` / `session_state` is the supplied `$sessionId`
     * rather than the offline session's own id: when this is built from an
     * auth-code exchange the online SSO session is still live, and the
     * login-status iframe (F-38) hashes that SSO id against the `AUTH_SESSION`
     * cookie -- so the two must agree. Keycloak parity: the iframe tracks the
     * SSO session, not the offline grant. Pass the offline session id only
     * when no live SSO session exists (offline refresh). The offline record's
     * own id remains the source of truth for persistence/lookup.
     *
     * @param non-empty-string $sessionId SSO session id to advertise when live;
     *        the offline session id when refreshing without an SSO session.
     */
    public function createOfflineTokenBundle(
        Realm $realm,
        OfflineSession $offlineSession,
        Client $client,
        User $user,
        string $sessionId
    ): array {
        $context = GrantContext::fromOfflineSession($offlineSession)->withSid($sessionId);

        return $this->createTokenBundleFromContext(
            $realm,
            $context,
            $client,
            $user,
            RefreshTokenKind::Offline
        );
    }

    public function createTokenBundle(
        Realm $realm,
        Session $session,
        Login $login,
        Client $client,
        User $user
    ): array {
        return $this->createTokenBundleFromContext(
            $realm,
            GrantContext::fromSession($session, $login),
            $client,
            $user,
            RefreshTokenKind::Sso
        );
    }

    /**
     * Assembles the access/id/refresh triple from a shared grant context.
     */
    private function createTokenBundleFromContext(
        Realm $realm,
        GrantContext $context,
        Client $client,
        User $user,
        RefreshTokenKind $refreshKind
    ): array {
        $now = time();
        $refreshExpiresIn = $refreshKind->expiresIn($realm);

        // Scope and role claims are resolved once per issuance: role scope
        // mappings narrow the stored grant and filter the emitted roles.
        // The User model carries no authorization state.
        $issued = $this->scopeResolver->resolveIssuance($context->scope, $user, $client);
        $context = $context->withScope($issued->scope);
        $roleClaims = $issued->roleClaims;

        $accessToken = $this->createAccessToken($now, $realm, $context, $client, $user, $roleClaims);
        $idToken = $this->createIdToken($now, $realm, $context, $client, $user, $accessToken);
        $refreshToken = $this->createRefreshToken($now, $realm, $context, $client, $user, $roleClaims, $refreshKind);

        return [
            "access_token" => $accessToken,
            "expires_in" => $realm->getAccessTokenExpiresIn(),
            "refresh_expires_in" => $refreshExpiresIn,
            "refresh_token" => $refreshToken,
            "token_type" => "Bearer",
            "id_token" => $idToken,
            "not-before-policy" => 0,
            "session_state" => $context->sid,
            "scope" => $context->scope,
        ];
    }

    private function createRefreshToken(
        int $now,
        Realm $realm,
        GrantContext $context,
        Client $client,
        User $user,
        RoleClaims $roleClaims,
        RefreshTokenKind $kind
    ): string {
        $claims = array_merge(
            $this->baseClaims($now, $now + $kind->expiresIn($realm), $realm, $context, $client),
            [
                "aud" => $this->issuer,
                "typ" => $kind->value,
                "realm_access" => [
                    "roles" => $roleClaims->realmRoles
                ],
                "scope" => $context->scope,
                "sid" => $context->sid
            ]
        );
        if ($roleClaims->resourceAccess !== null) {
            $claims["resource_access"] = $roleClaims->resourceAccess;
        }
        return $this->createToken($claims, $realm->getKeysId());
    }

    /**
     * Registered claims shared by every token of an issuance. Each caller
     * adds its own `aud`, `typ` and token-specific claims on top.
     */
    private function baseClaims(
        int $now,
        int $exp,
        Realm $realm,
        GrantContext $context,
        Client $client
    ): array {
        return [
            "exp" => $exp,
            "iat" => $now,
            "jti" => getGuid(),
            "iss" => $this->issuerFor($realm),
            "sub" => $context->subject,
            "azp" => $client->getName(),
            "session_state" => $context->sid,
        ];
    }

    private function createAccessToken(
        int $now,
        Realm $realm,
        GrantContext $context,
        Client $client,
        User $user,
        RoleClaims $roleClaims
    ): string {
        $claims = array_merge(
            $this->baseClaims($now, $now + $realm->getAccessTokenExpiresIn(), $realm, $context, $client),
            [
                "aud" => $client->getName(),
                "typ" => "Bearer",
                "auth_time" => $context->authTime,
                "acr" => $context->acr,
                "allowed-origins" => [
                    $client->getUri()
                ],
                "realm_access" => [
                    "roles" => $roleClaims->realmRoles
                ],
                "scope" => $context->scope,
                "sid" => $context->sid,
                "preferred_username" => $user->getName()
            ]
        );
        if ($roleClaims->resourceAccess !== null) {
            $claims["resource_access"] = $roleClaims->resourceAccess;
        }
        return $this->createToken($claims, $realm->getKeysId());
    }

    private function createIdToken(
        int $now,
        Realm $realm,
        GrantContext $context,
        Client $client,
        User $user,
        string $accessToken
    ): string {
        $claims = array_merge(
            $this->baseClaims($now, $now + $realm->getAccessTokenExpiresIn(), $realm, $context, $client),
            [
                "aud" => $client->getName(),
                "typ" => "ID",
                "auth_time" => $context->authTime,
                "at_hash" => self::calculateAtHash($accessToken),
                "acr" => $context->acr,
                "sid" => $context->sid,
                "preferred_username" => $user->getName()
            ]
        );
        // Keycloak parity (F-42): `nonce` belongs in the ID token only, and
        // only when the auth request carried one.
        if ($context->nonce !== null && $context->nonce !== '') {
            $claims["nonce"] = $context->nonce;
        }
        return $this->createToken($claims, $realm->getKeysId());
    }

    private function issuerFor(Realm $realm): string
    {
        return $this->issuer . '/realms/' . $realm->getName();
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
