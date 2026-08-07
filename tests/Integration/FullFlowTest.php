<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Interfaces\SessionCookieHandler;
use AuthServer\Services\InMemorySessionCookieHandler;
use AuthServer\Tests\Support\TestAppFactory;
use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Factory\ServerRequestFactory;

class FullFlowTest extends TestCase
{
    private static \Slim\App $app;
    private static string $issuer = 'http://localhost:8000';

    public static function setUpBeforeClass(): void
    {
        self::$app = TestAppFactory::createApp();
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

    // ── Auth endpoint renders login form ─────────────────────

    public function testAuthEndpointReturnsLoginForm(): void
    {
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/auth', [
            'client_id' => 'local',
            'redirect_uri' => 'http://localhost:5173',
            'response_type' => 'code',
            'response_mode' => 'query',
            'scope' => 'openid',
            'state' => 'st',
            'nonce' => 'nc',
        ]);

        $response = $this->handle($request);

        self::assertSame(200, $response->getStatusCode());
        $body = (string) $response->getBody();
        self::assertStringContainsString('login', $body);
    }

    // ── Auth fails with invalid client ────────────────────────

    public function testAuthWithInvalidClientReturns400(): void
    {
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/auth', [
            'client_id' => 'ghost',
            'redirect_uri' => 'http://example.com',
            'response_type' => 'code',
            'response_mode' => 'query',
            'scope' => 'openid',
            'state' => 'st',
            'nonce' => 'nc',
        ]);

        $response = $this->handle($request);
        self::assertSame(400, $response->getStatusCode());
    }

    // ── Full login flow ───────────────────────────────────────

    public function testLoginWithWrongPasswordShowsForm(): void
    {
        // Step 1: GET /auth to get login form
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/auth', [
            'client_id' => 'local',
            'redirect_uri' => 'http://localhost:5173',
            'response_type' => 'code',
            'response_mode' => 'query',
            'scope' => 'openid',
            'state' => 'st',
            'nonce' => 'nc',
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
        $body = (string) $response->getBody();

        preg_match('/action="[^"]*\?q=([^"]+)"/', $body, $m);
        self::assertNotEmpty($m, 'login_id not found in form');
        $loginId = $m[1];

        preg_match('/name="csrf_token"\s*value="([^"]+)"/', $body, $m);
        self::assertNotEmpty($m, 'csrf_token not found in form');
        $csrfToken = $m[1];

        // Step 2: POST login with wrong password
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/login-actions/authenticate', ['q' => $loginId], [
            'email' => 'test@example.com',
            'password' => 'wrong-password',
            'csrf_token' => $csrfToken,
        ]);

        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
        $body = (string) $response->getBody();
        self::assertStringContainsString('invalid password', $body);
    }

    public function testFullLoginFlow(): array
    {
        // Step 1: GET /auth
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/auth', [
            'client_id' => 'local',
            'redirect_uri' => 'http://localhost:5173',
            'response_type' => 'code',
            'response_mode' => 'query',
            'scope' => 'openid',
            'state' => 'st',
            'nonce' => 'nc',
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
        $body = (string) $response->getBody();

        preg_match('/action="[^"]*\?q=([^"]+)"/', $body, $m);
        self::assertNotEmpty($m, 'login_id not found');
        $loginId = $m[1];

        preg_match('/name="csrf_token"\s*value="([^"]+)"/', $body, $m);
        self::assertNotEmpty($m, 'csrf_token not found');
        $csrfToken = $m[1];

        // Step 2: POST login with correct password
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/login-actions/authenticate', ['q' => $loginId], [
            'email' => 'test@example.com',
            'password' => 'tst',
            'csrf_token' => $csrfToken,
        ]);

        $response = $this->handle($request);
        self::assertSame(302, $response->getStatusCode());
        $location = $response->getHeaderLine('Location');
        self::assertStringStartsWith('http://localhost:5173?code=', $location);
        self::assertStringContainsString('&state=st', $location);

        preg_match('/code=([^&]+)/', $location, $m);
        self::assertNotEmpty($m, 'code not found');
        $code = $m[1];

        // Step 3: POST token to exchange code
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token', [], [
            'grant_type' => 'authorization_code',
            'client_id' => 'local',
            'code' => $code,
            'redirect_uri' => 'http://localhost:5173',
            'refresh_token' => '',
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());

        $tokens = json_decode((string) $response->getBody(), true);
        self::assertNotNull($tokens);
        self::assertArrayHasKey('access_token', $tokens);
        self::assertArrayHasKey('refresh_token', $tokens);
        self::assertArrayHasKey('id_token', $tokens);
        self::assertSame('Bearer', $tokens['token_type']);
        self::assertSame(300, $tokens['expires_in']);

        // Return tokens for subsequent dependent tests
        return $tokens;
    }

    #[Depends('testFullLoginFlow')]
    public function testRefreshTokenFlow(array $tokens): void
    {
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token', [], [
            'grant_type' => 'refresh_token',
            'client_id' => 'local',
            'code' => '',
            'redirect_uri' => '',
            'refresh_token' => $tokens['refresh_token'],
        ]);

        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());

        $body = json_decode((string) $response->getBody(), true);
        self::assertNotNull($body);
        self::assertArrayHasKey('access_token', $body);
        self::assertArrayHasKey('refresh_token', $body);

        // Token rotation: new refresh token differs from old
        self::assertNotSame($tokens['refresh_token'], $body['refresh_token']);
    }

    // ── Certs endpoint ────────────────────────────────────────

    public function testCertsEndpointReturnsJwks(): void
    {
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/certs');
        $response = $this->handle($request);

        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertNotNull($body);
        self::assertArrayHasKey('keys', $body);
        self::assertCount(1, $body['keys']);
        self::assertSame('RS256', $body['keys'][0]['alg']);
    }

    // ── Well-known endpoint ───────────────────────────────────

    public function testWellKnownEndpoint(): void
    {
        $request = $this->createRequest('GET', '/realms/test/.well-known/openid-configuration');
        $response = $this->handle($request);

        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertNotNull($body);
        self::assertStringContainsString(self::$issuer . '/realms/test', $body['issuer']);
    }

    // ── UserInfo endpoint ─────────────────────────────────────

    #[Depends('testFullLoginFlow')]
    public function testUserInfoReturnsSubAndUsername(array $tokens): void
    {
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/userinfo', [], null, [
            'Authorization' => 'Bearer ' . $tokens['access_token'],
        ]);

        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());

        $body = json_decode((string) $response->getBody(), true);
        self::assertNotNull($body);
        self::assertArrayHasKey('sub', $body);
        self::assertArrayHasKey('preferred_username', $body);
        self::assertSame('emant_test', $body['preferred_username']);
    }

    // ── Logout endpoint ───────────────────────────────────────

    #[Depends('testFullLoginFlow')]
    public function testLogoutExpiresSession(array $tokens): void
    {
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/logout', [
            'id_token_hint' => $tokens['id_token'],
            'post_logout_redirect_uri' => 'http://localhost:5173',
        ]);

        $response = $this->handle($request);
        self::assertSame(302, $response->getStatusCode());
        self::assertStringStartsWith('http://localhost:5173', $response->getHeaderLine('Location'));
    }

    // ── PKCE flow ─────────────────────────────────────────────

    public function testPkceFlow(): void
    {
        $codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
        $codeChallenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');

        // Step 1: GET /auth with code_challenge
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/auth', [
            'client_id' => 'local',
            'redirect_uri' => 'http://localhost:5173',
            'response_type' => 'code',
            'response_mode' => 'query',
            'scope' => 'openid',
            'state' => 'pkce-st',
            'nonce' => 'pkce-nc',
            'code_challenge_method' => 'S256',
            'code_challenge' => $codeChallenge,
        ]);

        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
        $body = (string) $response->getBody();

        preg_match('/action="[^"]*\?q=([^"]+)"/', $body, $m);
        $loginId = $m[1];
        preg_match('/name="csrf_token"\s*value="([^"]+)"/', $body, $m);
        $csrfToken = $m[1];

        // Step 2: POST login
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/login-actions/authenticate', ['q' => $loginId], [
            'email' => 'test@example.com',
            'password' => 'tst',
            'csrf_token' => $csrfToken,
        ]);

        $response = $this->handle($request);
        self::assertSame(302, $response->getStatusCode());
        preg_match('/code=([^&]+)/', $response->getHeaderLine('Location'), $m);
        $pkceCode = $m[1];

        // Step 3: Exchange code with verifier
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token', [], [
            'grant_type' => 'authorization_code',
            'client_id' => 'local',
            'code' => $pkceCode,
            'redirect_uri' => 'http://localhost:5173',
            'refresh_token' => '',
            'code_verifier' => $codeVerifier,
        ]);

        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
        $tokens = json_decode((string) $response->getBody(), true);
        self::assertArrayHasKey('access_token', $tokens);
    }

    public function testPkceExchangeWithoutVerifierReturns400(): void
    {
        $handler = self::$app->getContainer()->get(SessionCookieHandler::class);
        if ($handler instanceof InMemorySessionCookieHandler) {
            $handler->reset();
        }

        $codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
        $codeChallenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');

        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/auth', [
            'client_id' => 'local',
            'redirect_uri' => 'http://localhost:5173',
            'response_type' => 'code',
            'response_mode' => 'query',
            'scope' => 'openid',
            'state' => 'pkce-missing-v-st',
            'nonce' => 'pkce-missing-v-nc',
            'code_challenge_method' => 'S256',
            'code_challenge' => $codeChallenge,
        ]);

        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
        $body = (string) $response->getBody();

        preg_match('/action="[^"]*\?q=([^"]+)"/', $body, $m);
        $loginId = $m[1];
        preg_match('/name="csrf_token"\s*value="([^"]+)"/', $body, $m);
        $csrfToken = $m[1];

        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/login-actions/authenticate', ['q' => $loginId], [
            'email' => 'test@example.com',
            'password' => 'tst',
            'csrf_token' => $csrfToken,
        ]);

        $response = $this->handle($request);
        self::assertSame(302, $response->getStatusCode());
        preg_match('/code=([^&]+)/', $response->getHeaderLine('Location'), $m);
        $pkceCode = $m[1];

        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token', [], [
            'grant_type' => 'authorization_code',
            'client_id' => 'local',
            'code' => $pkceCode,
            'redirect_uri' => 'http://localhost:5173',
            'refresh_token' => '',
        ]);

        $response = $this->handle($request);
        self::assertSame(400, $response->getStatusCode());
        $error = json_decode((string) $response->getBody(), true);
        self::assertSame('Invalid request', $error['error']);
        self::assertStringContainsString('code_verifier', $error['error_description']);
    }

    // ── SSO: no session cookie → shows login form ─────────────

    public function testSsoWithoutCookieShowsLoginForm(): void
    {
        $request = $this->createRequest('GET', '/realms/web/protocol/openid-connect/auth', [
            'client_id' => 'playground',
            'redirect_uri' => 'https://em-ant.gitlab.io/react-playground',
            'response_type' => 'code',
            'response_mode' => 'query',
            'scope' => 'openid',
            'state' => 'sso-st',
            'nonce' => 'sso-nc',
        ]);

        $response = $this->handle($request);
        $body = (string) $response->getBody();
        self::assertStringContainsString('login', $body);
    }
}
