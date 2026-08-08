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
    private const PKCE_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

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

    // ── Shared flow helpers ───────────────────────────────────

    private function getAuthForm(
        string $state,
        string $nonce,
        array $extra = [],
        string $clientId = 'local',
        string $redirectUri = 'http://localhost:5173',
        string $realm = 'test',
    ): ResponseInterface {
        $request = $this->createRequest('GET', '/realms/' . $realm . '/protocol/openid-connect/auth', array_merge([
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'response_type' => 'code',
            'response_mode' => 'query',
            'scope' => 'openid',
            'state' => $state,
            'nonce' => $nonce,
        ], $extra));

        return $this->handle($request);
    }

    private function parseLoginForm(string $body): array
    {
        preg_match('/action="[^"]*\?q=([^"]+)"/', $body, $m);
        self::assertNotEmpty($m, 'login_id not found in login form');
        $loginId = $m[1];

        preg_match('/name="csrf_token"\s*value="([^"]+)"/', $body, $m);
        self::assertNotEmpty($m, 'csrf_token not found in login form');
        $csrfToken = $m[1];

        return ['loginId' => $loginId, 'csrfToken' => $csrfToken];
    }

    private function login(string $loginId, string $csrfToken, string $password, string $email = 'test@example.com'): ResponseInterface
    {
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/login-actions/authenticate', ['q' => $loginId], [
            'email' => $email,
            'password' => $password,
            'csrf_token' => $csrfToken,
        ]);

        return $this->handle($request);
    }

    private function extractCode(string $location): string
    {
        preg_match('/code=([^&]+)/', $location, $m);
        self::assertNotEmpty($m, 'authorization code not found in redirect location');

        return $m[1];
    }

    private function pkceChallenge(string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }

    private function resetSessionCookie(): void
    {
        $handler = self::$app->getContainer()->get(SessionCookieHandler::class);
        if ($handler instanceof InMemorySessionCookieHandler) {
            $handler->reset();
        }
    }

    private function promptAuth(
        string $state,
        string $redirectUri,
        string $clientId = 'local',
        string $realm = 'test',
    ): ResponseInterface {
        $request = $this->createRequest(
            'GET',
            '/realms/' . $realm . '/protocol/openid-connect/auth',
            [
                'client_id' => $clientId,
                'redirect_uri' => $redirectUri,
                'response_type' => 'code',
                'response_mode' => 'query',
                'scope' => 'openid',
                'state' => $state,
                'nonce' => 'nc',
                'prompt' => 'none',
            ]
        );

        return $this->handle($request);
    }

    private function requestLogout(string $idToken, string $postLogoutRedirectUri = ''): ResponseInterface
    {
        $query = ['id_token_hint' => $idToken];
        if ($postLogoutRedirectUri !== '') {
            $query['post_logout_redirect_uri'] = $postLogoutRedirectUri;
        }

        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/logout', $query);

        return $this->handle($request);
    }

    private function exchangeCode(string $code, array $extra = []): ResponseInterface
    {
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token', [], array_merge([
            'grant_type' => 'authorization_code',
            'client_id' => 'local',
            'code' => $code,
            'redirect_uri' => 'http://localhost:5173',
            'refresh_token' => '',
        ], $extra));

        return $this->handle($request);
    }

    private function getFormAndLogin(string $state, string $nonce, string $password, array $authExtra = []): array
    {
        $formResponse = $this->getAuthForm($state, $nonce, $authExtra);
        $form = $this->parseLoginForm((string) $formResponse->getBody());
        $response = $this->login($form['loginId'], $form['csrfToken'], $password);

        return [$formResponse, $response];
    }

    private function completeLogin(string $state, string $nonce, array $authExtra = [], array $tokenExtra = []): array
    {
        [, $loginResponse] = $this->getFormAndLogin($state, $nonce, 'tst', $authExtra);
        self::assertSame(302, $loginResponse->getStatusCode(), 'login should redirect');
        $location = $loginResponse->getHeaderLine('Location');
        self::assertStringStartsWith('http://localhost:5173?code=', $location);
        self::assertStringContainsString('state=' . $state, $location);
        $code = $this->extractCode($location);

        $tokenResponse = $this->exchangeCode($code, $tokenExtra);
        self::assertSame(200, $tokenResponse->getStatusCode(), 'token exchange should succeed');

        return $this->decodeJson($tokenResponse);
    }

    private function decodeJson(ResponseInterface $response): array
    {
        $body = json_decode((string) $response->getBody(), true);
        self::assertNotNull($body, 'response should be valid JSON');

        return $body;
    }

    // ── Auth endpoint renders login form ─────────────────────

    public function testAuthEndpointReturnsLoginForm(): void
    {
        $response = $this->getAuthForm('st', 'nc');

        self::assertSame(200, $response->getStatusCode());
        self::assertStringContainsString('login', (string) $response->getBody());
    }

    // ── Auth fails with invalid client ────────────────────────

    public function testAuthWithInvalidClientReturns400(): void
    {
        $response = $this->getAuthForm('st', 'nc', clientId: 'ghost', redirectUri: 'http://example.com');

        self::assertSame(400, $response->getStatusCode());
    }

    // ── Full login flow ───────────────────────────────────────

    public function testLoginWithWrongPasswordShowsForm(): void
    {
        [$formResponse, $response] = $this->getFormAndLogin('st', 'nc', 'wrong-password');

        self::assertSame(200, $formResponse->getStatusCode());
        self::assertSame(200, $response->getStatusCode());
        self::assertStringContainsString('invalid password', (string) $response->getBody());
    }

    public function testFullLoginFlow(): array
    {
        $tokens = $this->completeLogin('st', 'nc');

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

        $body = $this->decodeJson($response);
        self::assertArrayHasKey('access_token', $body);
        self::assertArrayHasKey('refresh_token', $body);

        // Token rotation: new refresh token differs from old
        self::assertNotSame($tokens['refresh_token'], $body['refresh_token']);
    }

    // ── Certs endpoint ────────────────────────────────────────

    public function testCertsEndpointReturnsJwks(): void
    {
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/certs');
        $body = $this->decodeJson($this->handle($request));

        self::assertArrayHasKey('keys', $body);
        self::assertCount(1, $body['keys']);
        self::assertSame('RS256', $body['keys'][0]['alg']);
    }

    // ── Well-known endpoint ───────────────────────────────────

    public function testWellKnownEndpoint(): void
    {
        $request = $this->createRequest('GET', '/realms/test/.well-known/openid-configuration');
        $body = $this->decodeJson($this->handle($request));

        self::assertStringContainsString(self::$issuer . '/realms/test', $body['issuer']);
    }

    // ── UserInfo endpoint ─────────────────────────────────────

    #[Depends('testFullLoginFlow')]
    public function testUserInfoReturnsSubAndUsername(array $tokens): void
    {
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/userinfo', [], null, [
            'Authorization' => 'Bearer ' . $tokens['access_token'],
        ]);

        $body = $this->decodeJson($this->handle($request));
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

    // ── Logout redirect validation ────────────────────────────

    public function testLogoutAcceptsSubpathOfRegisteredUri(): void
    {
        $tokens = $this->completeLogin('logout-sub-st', 'logout-sub-nc');

        $response = $this->requestLogout($tokens['id_token'], 'http://localhost:5173/logged-out');

        self::assertSame(302, $response->getStatusCode());
        self::assertSame('http://localhost:5173/logged-out', $response->getHeaderLine('Location'));
    }

    public function testLogoutRejectsUnregisteredUri(): void
    {
        $tokens = $this->completeLogin('logout-bad-st', 'logout-bad-nc');

        $response = $this->requestLogout($tokens['id_token'], 'http://evil.com');

        self::assertSame(204, $response->getStatusCode());
        self::assertSame('', $response->getHeaderLine('Location'));
    }

    public function testLogoutWithoutIdTokenDoesNotRedirect(): void
    {
        $this->resetSessionCookie();

        $response = $this->requestLogout('', 'http://localhost:5173');

        self::assertSame(204, $response->getStatusCode());
        self::assertSame('', $response->getHeaderLine('Location'));
    }

    // ── prompt=none ────────────────────────────────────────────

    public function testPromptNoneWithoutSessionRedirectsWithLoginRequired(): void
    {
        $this->resetSessionCookie();

        $response = $this->promptAuth('pn-st', 'http://localhost:5173');

        self::assertSame(302, $response->getStatusCode());
        $location = $response->getHeaderLine('Location');
        self::assertStringStartsWith('http://localhost:5173', $location);
        self::assertStringContainsString('error=login_required', $location);
        self::assertStringContainsString('state=pn-st', $location);
    }

    public function testPromptNoneWithUnregisteredRedirectDoesNotRedirect(): void
    {
        $this->resetSessionCookie();

        $response = $this->promptAuth('pn-bad', 'http://evil.com');

        self::assertSame(302, $response->getStatusCode());
        $location = $response->getHeaderLine('Location');
        self::assertStringNotContainsString('http://evil.com', $location);
        self::assertStringContainsString('/protocol/openid-connect/error', $location);
    }

    public function testPromptNoneWithValidSessionReturnsCode(): void
    {
        $this->resetSessionCookie();

        [, $loginResponse] = $this->getFormAndLogin('pn-ses-st', 'pn-ses-nc', 'tst');
        self::assertSame(302, $loginResponse->getStatusCode());

        $response = $this->promptAuth('pn-ses-2-st', 'http://localhost:5173');

        self::assertSame(302, $response->getStatusCode());
        $location = $response->getHeaderLine('Location');
        self::assertStringStartsWith('http://localhost:5173?code=', $location);
        self::assertStringContainsString('state=pn-ses-2-st', $location);
    }

    public function testPromptNoneMissingScopeReturns400(): void
    {
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/auth', [
            'client_id' => 'local',
            'redirect_uri' => 'http://localhost:5173',
            'response_type' => 'code',
            'response_mode' => 'query',
            'state' => 'st',
            'nonce' => 'nc',
            'prompt' => 'none',
        ]);

        $response = $this->handle($request);
        self::assertSame(400, $response->getStatusCode());
        self::assertStringContainsString('scope', $this->decodeJson($response)['error_description']);
    }

    public function testPromptNoneMissingClientIdReturns400(): void
    {
        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/auth', [
            'redirect_uri' => 'http://localhost:5173',
            'response_type' => 'code',
            'response_mode' => 'query',
            'scope' => 'openid',
            'state' => 'st',
            'nonce' => 'nc',
            'prompt' => 'none',
        ]);

        $response = $this->handle($request);
        self::assertSame(400, $response->getStatusCode());
        self::assertStringContainsString('client_id', $this->decodeJson($response)['error_description']);
    }

    // ── PKCE flow ─────────────────────────────────────────────

    public function testPkceFlow(): void
    {
        $this->resetSessionCookie();

        $codeChallenge = $this->pkceChallenge(self::PKCE_VERIFIER);

        $tokens = $this->completeLogin('pkce-st', 'pkce-nc', [
            'code_challenge_method' => 'S256',
            'code_challenge' => $codeChallenge,
        ], [
            'code_verifier' => self::PKCE_VERIFIER,
        ]);

        self::assertArrayHasKey('access_token', $tokens);
    }

    public function testPkceExchangeWithoutVerifierReturns400(): void
    {
        $handler = self::$app->getContainer()->get(SessionCookieHandler::class);
        if ($handler instanceof InMemorySessionCookieHandler) {
            $handler->reset();
        }

        $codeChallenge = $this->pkceChallenge(self::PKCE_VERIFIER);

        [, $loginResponse] = $this->getFormAndLogin('pkce-missing-v-st', 'pkce-missing-v-nc', 'tst', [
            'code_challenge_method' => 'S256',
            'code_challenge' => $codeChallenge,
        ]);
        self::assertSame(302, $loginResponse->getStatusCode());
        $code = $this->extractCode($loginResponse->getHeaderLine('Location'));

        $response = $this->exchangeCode($code);
        self::assertSame(400, $response->getStatusCode());
        $error = $this->decodeJson($response);
        self::assertSame('Invalid request', $error['error']);
        self::assertStringContainsString('code_verifier', $error['error_description']);
    }

    // ── SSO: no session cookie → shows login form ─────────────

    public function testSsoWithoutCookieShowsLoginForm(): void
    {
        $response = $this->getAuthForm(
            'sso-st',
            'sso-nc',
            clientId: 'playground',
            redirectUri: 'https://em-ant.gitlab.io/react-playground',
            realm: 'web',
        );

        self::assertStringContainsString('login', (string) $response->getBody());
    }
}
