<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Tests\Support\IntegrationFlowTrait;
use AuthServer\Tests\Support\TestAppFactory;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

class TokenLifecycleTest extends TestCase
{
    use IntegrationFlowTrait;

    private static \Slim\App $app;
    private static \AuthServer\Services\InMemorySessionCookieHandler $sessionCookieHandler;

    public static function setUpBeforeClass(): void
    {
        self::$app = TestAppFactory::createApp();
        self::$sessionCookieHandler = self::$app->getContainer()->get(
            \AuthServer\Interfaces\SessionCookieHandler::class
        );
    }

    protected function setUp(): void
    {
        self::$sessionCookieHandler->reset();
    }

    private function revoke(string $token, string $clientId, ?string $hint = null): ResponseInterface
    {
        $body = ['token' => $token, 'client_id' => $clientId];
        if ($hint !== null) {
            $body['token_type_hint'] = $hint;
        }
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/revoke', [], $body);
        return $this->handle($request);
    }

    private function refresh(string $refreshToken, string $clientId = 'local'): ResponseInterface
    {
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token', [], [
            'grant_type' => 'refresh_token',
            'client_id' => $clientId,
            'refresh_token' => $refreshToken,
        ]);
        return $this->handle($request);
    }

    private function userinfo(string $token): ResponseInterface
    {
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/userinfo', [], null, [
            'Authorization' => 'Bearer ' . $token,
        ]);
        return $this->handle($request);
    }

    // ── Revocation endpoint tests ────────────────────────────

    public function testWellKnownIncludesRevocationEndpoint(): void
    {
        $request = $this->createRequest('GET', '/realms/test/.well-known/openid-configuration');
        $response = $this->handle($request);

        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertNotNull($body);

        self::assertStringContainsString(
            '/protocol/openid-connect/revoke',
            $body['revocation_endpoint']
        );
        self::assertContains(
            'client_secret_basic',
            $body['revocation_endpoint_auth_methods_supported']
        );
    }

    public function testRevokeGarbageTokenReturns200(): void
    {
        $response = $this->revoke('not-a-valid-jwt', 'local');

        self::assertSame(200, $response->getStatusCode());
    }

    public function testRevokeRefreshToken(): void
    {
        $tokens = $this->doFullLogin();

        $response = $this->revoke($tokens['refresh_token'], 'local');
        self::assertSame(200, $response->getStatusCode());

        $response = $this->refresh($tokens['refresh_token']);
        self::assertSame(400, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertStringContainsString('expired', strtolower($body['error_description'] ?? ''));
    }

    public function testRevokeRefreshTokenWithoutHint(): void
    {
        $tokens = $this->doFullLogin();

        // Omitting token_type_hint — server should treat it as refresh token
        $response = $this->revoke($tokens['refresh_token'], 'local');
        self::assertSame(200, $response->getStatusCode());

        // Confirm refresh is dead
        $response = $this->refresh($tokens['refresh_token']);
        self::assertSame(400, $response->getStatusCode());
    }

    public function testRevokeAccessTokenAndRejectAtUserinfo(): void
    {
        $tokens = $this->doFullLogin();

        $response = $this->revoke($tokens['access_token'], 'local', 'access_token');
        self::assertSame(200, $response->getStatusCode());

        $response = $this->userinfo($tokens['access_token']);
        self::assertSame(401, $response->getStatusCode());
    }

    public function testCrossClientRevocationSilentlyIgnored(): void
    {
        $tokens = $this->doFullLogin();

        // Try to revoke as a different client (kc_app vs local)
        $response = $this->revoke($tokens['access_token'], 'kc_app', 'access_token');
        self::assertSame(200, $response->getStatusCode());

        // Token should still be valid for the original client (local)
        $response = $this->userinfo($tokens['access_token']);
        self::assertSame(200, $response->getStatusCode());
    }

    public function testNewTokenAfterRevocationWorks(): void
    {
        $tokens = $this->doFullLogin();

        $this->revoke($tokens['access_token'], 'local', 'access_token');

        // Get new tokens via refresh
        $response = $this->refresh($tokens['refresh_token']);
        self::assertSame(200, $response->getStatusCode());
        $newTokens = json_decode((string) $response->getBody(), true);

        // New access token should work at userinfo
        $response = $this->userinfo($newTokens['access_token']);
        self::assertSame(200, $response->getStatusCode());
    }
}
