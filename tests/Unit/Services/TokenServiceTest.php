<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Services;

use AuthServer\Interfaces\KeyStore;
use AuthServer\Models\KeySet;
use AuthServer\Models\Client;
use AuthServer\Models\Login;
use AuthServer\Models\Realm;
use AuthServer\Models\Session;
use AuthServer\Models\User;
use AuthServer\Services\Base64Utils;
use AuthServer\Services\TokenService;
use PHPUnit\Framework\TestCase;

class TokenServiceTest extends TestCase
{
    private const KID = '33ce4036-0a36-45b9-ba74-6087d03c3b35';
    private const ISSUER = 'http://localhost:8000';

    private TokenService $tokenService;
    private KeySet $keySet;
    private Realm $realm;
    private Session $session;
    private Login $login;
    private Client $client;
    private User $user;

    protected function setUp(): void
    {
        $keysDir = __DIR__ . '/../../../keys/' . self::KID;
        $this->keySet = new KeySet(
            publicKey: file_get_contents("$keysDir/public_key.pem"),
            privateKey: file_get_contents("$keysDir/private_key.pem"),
            cert: file_get_contents("$keysDir/cert.pem"),
            jwks: json_decode(file_get_contents("$keysDir/keys.json"), true),
        );

        $keyStore = new class ($this->keySet) implements KeyStore {
            public function __construct(private KeySet $keySet) {}
            public function findKeys(string $kid): KeySet
            {
                return $this->keySet;
            }
        };

        $this->tokenService = new TokenService(self::ISSUER, $keyStore);

        $this->realm = new Realm(
            id: 'r-id',
            name: 'test',
            keys_id: self::KID,
            refresh_token_expires_in: 1800,
            access_token_expires_in: 300,
            pending_login_expires_in: 300,
            authenticated_login_expires_in: 300,
            session_expires_in: 86400,
            idle_session_expires_in: 1800,
            scope: 'openid profile',
            created_at: '2025-01-01 00:00:00',
        );

        $this->session = new Session(
            id: 'session-1',
            realm_id: 'r-id',
            user_id: 'user-1',
            acr: '0',
            created_at: '2025-01-01 00:00:00',
            status: 'ACTIVE',
        );

        $this->login = new Login(
            id: 'login-1',
            client_id: 'client-1',
            state: 'state-1',
            nonce: 'nonce-1',
            scope: 'openid',
            redirect_uri: 'https://example.com/cb',
            response_mode: 'query',
            created_at: '2025-01-01 00:00:00',
            session_id: 'session-1',
            authenticated_at: '2025-01-01 00:01:00',
            code: null,
            code_challenge: null,
            csrf_token: null,
            updated_at: null,
            refresh_token: null,
            status: 'AUTHENTICATED',
        );

        $this->client = new Client(
            id: 'client-1',
            name: 'my-app',
            realm_id: 'r-id',
            client_secret: null,
            uri: 'https://example.com',
            require_auth: false,
            created_at: '2025-01-01 00:00:00',
        );

        $this->user = $this->userWithClientRoles([]);
    }

    // ── createToken ───────────────────────────────────────────

    public function testCreateTokenReturnsValidJwtStructure(): void
    {
        $payload = ['sub' => 'user-1', 'exp' => time() + 300];
        $token = $this->tokenService->createToken($payload, self::KID);

        self::assertStringMatchesFormat('%S.%S.%S', $token);
        $parts = explode('.', $token);
        self::assertCount(3, $parts);
    }

    public function testCreateTokenHasCorrectHeader(): void
    {
        $payload = ['sub' => 'user-1', 'exp' => time() + 300];
        $token = $this->tokenService->createToken($payload, self::KID);
        $parts = explode('.', $token);
        $header = json_decode(Base64Utils::b64UrlDecode($parts[0]), true);

        self::assertSame('JWT', $header['typ']);
        self::assertSame('RS256', $header['alg']);
        self::assertSame(self::KID, $header['kid']);
    }

    // ── verifySignature ───────────────────────────────────────

    public function testVerifySignatureReturnsTrueForValidToken(): void
    {
        $payload = ['sub' => 'user-1', 'exp' => time() + 300];
        $token = $this->tokenService->createToken($payload, self::KID);

        self::assertTrue($this->tokenService->verifySignature($token, $this->realm));
    }

    public function testVerifySignatureReturnsFalseForTamperedToken(): void
    {
        $payload = ['sub' => 'user-1', 'exp' => time() + 300];
        $token = $this->tokenService->createToken($payload, self::KID);
        $parts = explode('.', $token);
        $tampered = $parts[0] . '.' . $parts[1] . '.invalidsignature';

        self::assertFalse($this->tokenService->verifySignature($tampered, $this->realm));
    }

    public function testVerifySignatureReturnsFalseForBadAlgorithm(): void
    {
        $header = Base64Utils::b64UrlEncode(json_encode(['typ' => 'JWT', 'alg' => 'HS256', 'kid' => self::KID]));
        $payload = Base64Utils::b64UrlEncode(json_encode(['sub' => 'user-1']));
        $token = "$header.$payload.fakesig";

        self::assertFalse($this->tokenService->verifySignature($token, $this->realm));
    }

    public function testVerifySignatureReturnsFalseForMalformedToken(): void
    {
        self::assertFalse($this->tokenService->verifySignature('not-a-jwt', $this->realm));
        self::assertFalse($this->tokenService->verifySignature('', $this->realm));
    }

    // ── decodeTokenPayload ────────────────────────────────────

    public function testDecodeTokenPayloadReturnsArray(): void
    {
        $payload = ['sub' => 'user-1', 'exp' => time() + 300, 'custom' => 'val'];
        $token = $this->tokenService->createToken($payload, self::KID);

        $decoded = $this->tokenService->decodeTokenPayload($token);
        self::assertSame('user-1', $decoded['sub']);
        self::assertSame('val', $decoded['custom']);
        self::assertArrayHasKey('exp', $decoded);
    }

    public function testDecodeTokenPayloadReturnsEmptyForMalformedToken(): void
    {
        self::assertSame([], $this->tokenService->decodeTokenPayload('not-a-jwt'));
    }

    public function testDecodeTokenSafelyReturnsNullForMalformedToken(): void
    {
        self::assertNull($this->tokenService->decodeTokenSafely('not-a-jwt'));
        self::assertNull($this->tokenService->decodeTokenSafely('a.b'));
    }

    // ── createTokenBundle (full integration of sub-methods) ───

    public function testCreateTokenBundleReturnsExpectedStructure(): void
    {
        $bundle = $this->tokenService->createTokenBundle(
            $this->realm,
            $this->session,
            $this->login,
            $this->client,
            $this->user,
        );

        self::assertArrayHasKey('access_token', $bundle);
        self::assertArrayHasKey('id_token', $bundle);
        self::assertArrayHasKey('refresh_token', $bundle);
        self::assertArrayHasKey('expires_in', $bundle);
        self::assertArrayHasKey('refresh_expires_in', $bundle);
        self::assertArrayHasKey('token_type', $bundle);
        self::assertArrayHasKey('session_state', $bundle);
        self::assertArrayHasKey('scope', $bundle);
        self::assertArrayHasKey('not-before-policy', $bundle);

        self::assertSame('Bearer', $bundle['token_type']);
        self::assertSame(300, $bundle['expires_in']);
        self::assertSame(1800, $bundle['refresh_expires_in']);
        self::assertSame('session-1', $bundle['session_state']);
        self::assertSame('openid', $bundle['scope']);
    }

    public function testAccessTokenContainsExpectedClaims(): void
    {
        $bundle = $this->tokenService->createTokenBundle(
            $this->realm, $this->session, $this->login, $this->client, $this->user,
        );
        $payload = $this->tokenService->decodeTokenPayload($bundle['access_token']);

        self::assertSame('user-1', $payload['sub']);
        self::assertSame('my-app', $payload['aud']);
        self::assertSame('Bearer', $payload['typ']);
        self::assertSame(self::ISSUER . '/realms/test', $payload['iss']);
        self::assertArrayHasKey('exp', $payload);
        self::assertArrayHasKey('iat', $payload);
        self::assertArrayHasKey('jti', $payload);
        self::assertArrayHasKey('auth_time', $payload);
        self::assertArrayHasKey('session_state', $payload);
        self::assertArrayHasKey('acr', $payload);
        self::assertSame('emant', $payload['preferred_username']);
        self::assertSame(['admin', 'basic'], $payload['realm_access']['roles']);
    }

    public function testAccessTokenOmitsResourceAccessWhenUserHasNoClientRoles(): void
    {
        $payload = $this->tokenService->decodeTokenPayload(
            $this->bundleForUser($this->user)['access_token']
        );

        self::assertArrayNotHasKey('resource_access', $payload);
    }

    /**
     * @param array<string, list<string>> $clientRoles
     */
    private function userWithClientRoles(array $clientRoles): User
    {
        return new User(
            id: 'user-1',
            realm_id: 'r-id',
            name: 'emant',
            email: 'test@example.com',
            password: 'hashed',
            realmRoles: ['admin', 'basic'],
            created_at: '2025-01-01 00:00:00',
            valid: true,
            clientRoles: $clientRoles,
        );
    }

    private function bundleForUser(User $user): array
    {
        return $this->tokenService->createTokenBundle(
            $this->realm, $this->session, $this->login, $this->client, $user,
        );
    }

    public function testAccessTokenCarriesClientRolesForResourceAccess(): void
    {
        $user = $this->userWithClientRoles(['my-app' => ['app-user', 'app-admin']]);

        $payload = $this->tokenService->decodeTokenPayload(
            $this->bundleForUser($user)['access_token']
        );

        self::assertSame(
            ['my-app' => ['roles' => ['app-user', 'app-admin']]],
            $payload['resource_access']
        );
    }

    public function testRefreshTokenCarriesClientRolesForResourceAccess(): void
    {
        $user = $this->userWithClientRoles(['my-app' => ['app-user']]);

        $payload = $this->tokenService->decodeTokenPayload(
            $this->bundleForUser($user)['refresh_token']
        );

        self::assertSame(
            ['my-app' => ['roles' => ['app-user']]],
            $payload['resource_access']
        );
    }

    public function testResourceAccessIsOmittedWhenUserHasNoRolesForTheTokenClient(): void
    {
        $user = $this->userWithClientRoles(['other-app' => ['viewer']]);

        $payload = $this->tokenService->decodeTokenPayload(
            $this->bundleForUser($user)['access_token']
        );

        self::assertArrayNotHasKey('resource_access', $payload);
    }

    public function testIdTokenContainsSpecCompliantAtHash(): void
    {
        $bundle = $this->tokenService->createTokenBundle(
            $this->realm, $this->session, $this->login, $this->client, $this->user,
        );
        $idPayload = $this->tokenService->decodeTokenPayload($bundle['id_token']);

        $hash = hash('sha256', $bundle['access_token'], true);
        $expected = Base64Utils::b64UrlEncode(substr($hash, 0, (int)(strlen($hash) / 2)));

        self::assertSame('ID', $idPayload['typ']);
        self::assertSame($expected, $idPayload['at_hash']);
        self::assertNotSame(md5($bundle['access_token']), $idPayload['at_hash']);
    }

    public function testRefreshTokenContainsExpectedClaims(): void
    {
        $bundle = $this->tokenService->createTokenBundle(
            $this->realm, $this->session, $this->login, $this->client, $this->user,
        );
        $payload = $this->tokenService->decodeTokenPayload($bundle['refresh_token']);

        self::assertSame('Refresh', $payload['typ']);
        self::assertArrayHasKey('exp', $payload);
    }

    public function testAllTokensValidateSuccessfully(): void
    {
        $bundle = $this->tokenService->createTokenBundle(
            $this->realm, $this->session, $this->login, $this->client, $this->user,
        );

        self::assertTrue($this->tokenService->verifySignature($bundle['access_token'], $this->realm));
        self::assertTrue($this->tokenService->verifySignature($bundle['id_token'], $this->realm));
        self::assertTrue($this->tokenService->verifySignature($bundle['refresh_token'], $this->realm));
    }
}
