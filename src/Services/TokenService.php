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
     * rather than the offline session's own id, so it matches the `AUTH_SESSION`
     * cookie the login-status iframe (F-38) verifies against. Callers must
     * pass the same value on every issuance for a grant: the auth-code
     * exchange passes the live SSO session id, and the offline-refresh path
     * re-passes the value embedded in the signed refresh token, keeping
     * session_state constant across rotations (Keycloak parity). The offline
     * record's own id remains the source of truth for persistence/lookup and
     * is the fallback for legacy tokens that carry no sid.
     *
     * @param non-empty-string $sessionId session id to advertise: the SSO
     *        session id, or the offline id for legacy grants without one.
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
}
