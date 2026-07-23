<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Tests\Support\TestAppFactory;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Factory\ServerRequestFactory;

class TokenLifecycleTest extends TestCase
{
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

    private function createRequest(string $method, string $path, array $query = [], mixed $body = null, array $headers = []): ServerRequestInterface
    {
        $uri = $path;
        if (!empty($query)) {
            $uri .= '?' . http_build_query($query);
        }
        $request = (new ServerRequestFactory())->createServerRequest($method, $uri);

        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        if ($body !== null) {
            $request->getBody()->write(is_string($body) ? $body : http_build_query($body));
            $request->getBody()->rewind();
            if (!is_string($body)) {
                $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');
            }
        }

        return $request;
    }

    private function handle(ServerRequestInterface $request): ResponseInterface
    {
        return self::$app->handle($request);
    }

    // ── Helper: full login flow to get tokens ────────────────

    private function doFullLogin(): array
    {
        // Step 1: GET /auth
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/auth', [
            'client_id' => 'local',
            'redirect_uri' => 'http://localhost:5173',
            'response_type' => 'code',
            'response_mode' => 'query',
            'scope' => 'openid',
            'state' => 'rev-st',
            'nonce' => 'rev-nc',
        ]);
        $response = $this->handle($request);
        $body = (string) $response->getBody();

        preg_match('/action="[^"]*\?q=([^"]+)"/', $body, $m);
        self::assertNotEmpty($m, 'login_id not found in auth response');
        $loginId = $m[1];

        preg_match('/name="csrf_token"\s*value="([^"]+)"/', $body, $m);
        self::assertNotEmpty($m, 'csrf_token not found in auth response');
        $csrfToken = $m[1];

        // Step 2: POST login
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/login-actions/authenticate', ['q' => $loginId], [
            'email' => 'test@example.com',
            'password' => 'tst',
            'csrf_token' => $csrfToken,
        ]);
        $response = $this->handle($request);
        self::assertSame(302, $response->getStatusCode(), 'login should redirect');
        $location = $response->getHeaderLine('Location');
        preg_match('/code=([^&]+)/', $location, $m);
        self::assertNotEmpty($m, 'code not found in login redirect');
        $code = $m[1];

        // Step 3: POST /token
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token', [], [
            'grant_type' => 'authorization_code',
            'client_id' => 'local',
            'code' => $code,
            'redirect_uri' => 'http://localhost:5173',
        ]);
        $response = $this->handle($request);
        return json_decode((string) $response->getBody(), true);
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
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/revoke', [], [
            'token' => 'not-a-valid-jwt',
            'client_id' => 'local',
        ]);
        $response = $this->handle($request);

        self::assertSame(200, $response->getStatusCode());
    }

    public function testRevokeRefreshToken(): void
    {
        $tokens = $this->doFullLogin();

        // Revoke the refresh token
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/revoke', [], [
            'token' => $tokens['refresh_token'],
            'client_id' => 'local',
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());

        // Try to refresh with the revoked token
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token', [], [
            'grant_type' => 'refresh_token',
            'client_id' => 'local',
            'refresh_token' => $tokens['refresh_token'],
        ]);
        $response = $this->handle($request);
        self::assertSame(400, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertStringContainsString('expired', strtolower($body['error_description'] ?? ''));
    }

    public function testRevokeRefreshTokenWithoutHint(): void
    {
        $tokens = $this->doFullLogin();

        // Omitting token_type_hint — server should treat it as refresh token
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/revoke', [], [
            'token' => $tokens['refresh_token'],
            'client_id' => 'local',
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());

        // Confirm refresh is dead
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token', [], [
            'grant_type' => 'refresh_token',
            'client_id' => 'local',
            'refresh_token' => $tokens['refresh_token'],
        ]);
        $response = $this->handle($request);
        self::assertSame(400, $response->getStatusCode());
    }

    public function testRevokeAccessTokenAndRejectAtUserinfo(): void
    {
        $tokens = $this->doFullLogin();

        // Revoke the access token
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/revoke', [], [
            'token' => $tokens['access_token'],
            'token_type_hint' => 'access_token',
            'client_id' => 'local',
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());

        // Try userinfo with revoked token
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/userinfo', [], null, [
            'Authorization' => 'Bearer ' . $tokens['access_token'],
        ]);
        $response = $this->handle($request);
        self::assertSame(401, $response->getStatusCode());
    }

    public function testCrossClientRevocationSilentlyIgnored(): void
    {
        $tokens = $this->doFullLogin();

        // Try to revoke as a different client (kc_app vs local)
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/revoke', [], [
            'token' => $tokens['access_token'],
            'token_type_hint' => 'access_token',
            'client_id' => 'kc_app',
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());

        // Token should still be valid for the original client (local)
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/userinfo', [], null, [
            'Authorization' => 'Bearer ' . $tokens['access_token'],
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
    }

    public function testNewTokenAfterRevocationWorks(): void
    {
        $tokens = $this->doFullLogin();

        // Revoke access token
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/revoke', [], [
            'token' => $tokens['access_token'],
            'token_type_hint' => 'access_token',
            'client_id' => 'local',
        ]);
        $this->handle($request);

        // Get new tokens via refresh
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token', [], [
            'grant_type' => 'refresh_token',
            'client_id' => 'local',
            'refresh_token' => $tokens['refresh_token'],
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
        $newTokens = json_decode((string) $response->getBody(), true);

        // New access token should work at userinfo
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/userinfo', [], null, [
            'Authorization' => 'Bearer ' . $newTokens['access_token'],
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
    }
}
