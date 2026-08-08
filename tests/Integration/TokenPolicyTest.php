<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Services\TokenService;
use AuthServer\Tests\Support\TestAppFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Factory\ServerRequestFactory;

class TokenPolicyTest extends TestCase
{
    private const KID = '2daca932-9ae0-411b-9bec-d8dac4cbe70b';
    private const ISSUER = 'http://localhost:8000';

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
            'state' => 'pol-st',
            'nonce' => 'pol-nc',
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

    private function decodeClaims(string $token): array
    {
        /** @var TokenService $tokenService */
        $tokenService = self::$app->getContainer()->get(TokenService::class);
        return $tokenService->decodeTokenPayload($token);
    }

    private function craftToken(string $typ, array $overrides = []): string
    {
        /** @var TokenService $tokenService */
        $tokenService = self::$app->getContainer()->get(TokenService::class);

        $now = time();
        $payload = array_merge(
            [
                'iss' => self::ISSUER . '/realms/test',
                'typ' => $typ,
                'aud' => 'local',
                'azp' => 'local',
                'exp' => $now + 300,
                'iat' => $now,
                'jti' => 'crafted-' . bin2hex(random_bytes(8)),
                'sub' => 'user-1',
            ],
            $overrides
        );

        return $tokenService->createToken($payload, self::KID);
    }

    public function testExpiredSignedAccessTokenReportsInactive(): void
    {
        $token = $this->craftToken('Bearer', ['exp' => time() - 1]);

        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token/introspect', [], [
            'token' => $token,
            'client_id' => 'local',
        ]);
        $response = $this->handle($request);
        $body = json_decode((string) $response->getBody(), true);

        self::assertSame(200, $response->getStatusCode());
        self::assertFalse($body['active']);
    }

    public function testExpiredSignedTokenRejectedAtUserinfo(): void
    {
        $token = $this->craftToken('Bearer', ['exp' => time() - 1]);

        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/userinfo', [], null, [
            'Authorization' => 'Bearer ' . $token,
        ]);
        $response = $this->handle($request);

        self::assertSame(401, $response->getStatusCode());
    }

    public function testTokenWithWrongIssuerReportsInactive(): void
    {
        $token = $this->craftToken('Bearer', ['iss' => self::ISSUER . '/realms/web']);

        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token/introspect', [], [
            'token' => $token,
            'client_id' => 'local',
        ]);
        $response = $this->handle($request);
        $body = json_decode((string) $response->getBody(), true);

        self::assertFalse($body['active']);
    }

    public function testInvalidSignatureTokenReportsInactive(): void
    {
        $token = $this->craftToken('Bearer');
        $parts = explode('.', $token);
        $tampered = $parts[0] . '.' . $parts[1] . '.badsignature';

        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token/introspect', [], [
            'token' => $tampered,
            'client_id' => 'local',
        ]);
        $response = $this->handle($request);
        $body = json_decode((string) $response->getBody(), true);

        self::assertFalse($body['active']);
    }

    public function testLogoutWithExpiredIdTokenHintStillSucceeds(): void
    {
        $tokens = $this->doFullLogin();
        $sid = $this->decodeClaims($tokens['id_token'])['sid'];
        $token = $this->craftToken('ID', ['exp' => time() - 1, 'sid' => $sid]);

        $request = $this->createRequest('GET', '/realms/test/protocol/openid-connect/logout', [
            'id_token_hint' => $token,
            'post_logout_redirect_uri' => 'http://localhost:5173',
        ]);
        $response = $this->handle($request);

        self::assertSame(302, $response->getStatusCode());
        self::assertStringContainsString(
            'http://localhost:5173',
            $response->getHeaderLine('Location')
        );

        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token', [], [
            'grant_type' => 'refresh_token',
            'client_id' => 'local',
            'refresh_token' => $tokens['refresh_token'],
        ]);
        $response = $this->handle($request);
        self::assertSame(400, $response->getStatusCode(), 'session should be gone after logout');
    }

    public function testRevocationOfExpiredTokenIsSilentlyIgnored(): void
    {
        $token = $this->craftToken('Bearer', ['exp' => time() - 1]);

        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/revoke', [], [
            'token' => $token,
            'token_type_hint' => 'access_token',
            'client_id' => 'local',
        ]);
        $response = $this->handle($request);

        self::assertSame(200, $response->getStatusCode());
    }
}