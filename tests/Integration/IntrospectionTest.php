<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Tests\Support\TestAppFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Factory\ServerRequestFactory;

class IntrospectionTest extends TestCase
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

    private function doFullLogin(): array
    {
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/auth', [
            'client_id' => 'local',
            'redirect_uri' => 'http://localhost:5173',
            'response_type' => 'code',
            'response_mode' => 'query',
            'scope' => 'openid',
            'state' => 'int-st',
            'nonce' => 'int-nc',
        ]);
        $response = $this->handle($request);
        $body = (string) $response->getBody();

        preg_match('/action="[^"]*\?q=([^"]+)"/', $body, $m);
        self::assertNotEmpty($m, 'login_id not found in auth response');
        $loginId = $m[1];

        preg_match('/name="csrf_token"\s*value="([^"]+)"/', $body, $m);
        self::assertNotEmpty($m, 'csrf_token not found in auth response');
        $csrfToken = $m[1];

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

        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token', [], [
            'grant_type' => 'authorization_code',
            'client_id' => 'local',
            'code' => $code,
            'redirect_uri' => 'http://localhost:5173',
        ]);
        $response = $this->handle($request);
        return json_decode((string) $response->getBody(), true);
    }

    // ── Introspect active access token ───────────────────────

    public function testWellKnownIncludesIntrospectionEndpoint(): void
    {
        $request = $this->createRequest('GET', '/realms/test/.well-known/openid-configuration');
        $response = $this->handle($request);

        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertNotNull($body);

        self::assertStringContainsString(
            '/protocol/openid-connect/token/introspect',
            $body['introspection_endpoint']
        );
        self::assertContains(
            'client_secret_basic',
            $body['introspection_endpoint_auth_methods_supported']
        );
    }

    public function testIntrospectActiveAccessToken(): void
    {
        $tokens = $this->doFullLogin();

        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token/introspect', [], [
            'token' => $tokens['access_token'],
            'client_id' => 'local',
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertNotNull($body);
        self::assertTrue($body['active']);
        self::assertArrayHasKey('sub', $body);
        self::assertArrayHasKey('aud', $body);
        self::assertArrayHasKey('iss', $body);
        self::assertArrayHasKey('exp', $body);
        self::assertArrayHasKey('iat', $body);
        self::assertArrayHasKey('jti', $body);
        self::assertArrayHasKey('token_type', $body);
        self::assertArrayHasKey('client_id', $body);
        self::assertArrayHasKey('scope', $body);
        self::assertArrayHasKey('sid', $body);
    }

    public function testIntrospectActiveRefreshToken(): void
    {
        $tokens = $this->doFullLogin();

        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token/introspect', [], [
            'token' => $tokens['refresh_token'],
            'client_id' => 'local',
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertNotNull($body);
        self::assertTrue($body['active']);
        self::assertSame('refresh_token', $body['token_type']);
    }

    public function testIntrospectRevokedAccessToken(): void
    {
        $tokens = $this->doFullLogin();

        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/revoke', [], [
            'token' => $tokens['access_token'],
            'token_type_hint' => 'access_token',
            'client_id' => 'local',
        ]);
        $this->handle($request);

        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token/introspect', [], [
            'token' => $tokens['access_token'],
            'client_id' => 'local',
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertNotNull($body);
        self::assertFalse($body['active']);
    }

    public function testCrossClientIntrospection(): void
    {
        $tokens = $this->doFullLogin();

        // First verify the token is valid for the original client
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token/introspect', [], [
            'token' => $tokens['access_token'],
            'client_id' => 'local',
        ]);
        $response = $this->handle($request);
        $body = json_decode((string) $response->getBody(), true);
        self::assertTrue($body['active'], 'token should be active for local; body: ' . json_encode($body));

        // Now introspect as a different client (kc_app)
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token/introspect', [], [
            'token' => $tokens['access_token'],
            'client_id' => 'kc_app',
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertNotNull($body);
        self::assertTrue($body['active'], 'cross-client introspection should return active; body: ' . json_encode($body));
        self::assertSame('local', $body['client_id']);
    }

    public function testIntrospectWithBadClientCredentials(): void
    {
        $tokens = $this->doFullLogin();

        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token/introspect', [], [
            'token' => $tokens['access_token'],
            'client_id' => 'nonexistent-client',
        ]);
        $response = $this->handle($request);
        self::assertSame(401, $response->getStatusCode());
    }

    public function testIntrospectGarbageToken(): void
    {
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token/introspect', [], [
            'token' => 'not-a-jwt',
            'client_id' => 'local',
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertNotNull($body);
        self::assertFalse($body['active']);
    }

    public function testIntrospectIdToken(): void
    {
        $tokens = $this->doFullLogin();

        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token/introspect', [], [
            'token' => $tokens['id_token'],
            'client_id' => 'local',
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertNotNull($body);
        self::assertTrue($body['active']);
        self::assertSame('ID', $body['token_type']);
        self::assertArrayHasKey('sub', $body);
    }

    public function testIntrospectWithTokenTypeHintMismatch(): void
    {
        $tokens = $this->doFullLogin();

        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token/introspect', [], [
            'token' => $tokens['access_token'],
            'token_type_hint' => 'refresh_token',
            'client_id' => 'local',
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertNotNull($body);
        self::assertTrue($body['active']);
    }

    public function testIntrospectMissingTokenReturns400(): void
    {
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token/introspect', [], [
            'client_id' => 'local',
        ]);
        $response = $this->handle($request);
        self::assertSame(400, $response->getStatusCode());
    }

    public function testIntrospectWithBasicAuth(): void
    {
        $tokens = $this->doFullLogin();

        $basic = base64_encode('local:tst');
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token/introspect', [], [
            'token' => $tokens['access_token'],
        ], [
            'Authorization' => 'Basic ' . $basic,
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertNotNull($body);
        self::assertTrue($body['active']);
    }
}