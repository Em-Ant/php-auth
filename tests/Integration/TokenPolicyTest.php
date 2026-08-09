<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Services\TokenService;
use AuthServer\Tests\Support\IntegrationFlowTrait;
use AuthServer\Tests\Support\TestAppFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

class TokenPolicyTest extends TestCase
{
    use IntegrationFlowTrait;
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

    private function introspect(string $token): array
    {
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token/introspect', [], [
            'token' => $token,
            'client_id' => 'local',
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
        return json_decode((string) $response->getBody(), true);
    }

    private function revoke(string $token): ResponseInterface
    {
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/revoke', [], [
            'token' => $token,
            'token_type_hint' => 'access_token',
            'client_id' => 'local',
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

    private function refresh(string $refreshToken): ResponseInterface
    {
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token', [], [
            'grant_type' => 'refresh_token',
            'client_id' => 'local',
            'refresh_token' => $refreshToken,
        ]);
        return $this->handle($request);
    }

    public function testExpiredSignedAccessTokenReportsInactive(): void
    {
        $token = $this->craftToken('Bearer', ['exp' => time() - 1]);
        $body = $this->introspect($token);

        self::assertFalse($body['active']);
    }

    public function testExpiredSignedTokenRejectedAtUserinfo(): void
    {
        $token = $this->craftToken('Bearer', ['exp' => time() - 1]);
        $response = $this->userinfo($token);

        self::assertSame(401, $response->getStatusCode());
    }

    public function testTokenWithWrongIssuerReportsInactive(): void
    {
        $token = $this->craftToken('Bearer', ['iss' => self::ISSUER . '/realms/web']);
        $body = $this->introspect($token);

        self::assertFalse($body['active']);
    }

    public function testInvalidSignatureTokenReportsInactive(): void
    {
        $token = $this->craftToken('Bearer');
        $parts = explode('.', $token);
        $tampered = $parts[0] . '.' . $parts[1] . '.badsignature';

        $body = $this->introspect($tampered);
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

        $response = $this->refresh($tokens['refresh_token']);
        self::assertSame(400, $response->getStatusCode(), 'session should be gone after logout');
    }

    public function testRevocationOfExpiredTokenIsSilentlyIgnored(): void
    {
        $token = $this->craftToken('Bearer', ['exp' => time() - 1]);
        $response = $this->revoke($token);

        self::assertSame(200, $response->getStatusCode());
    }
}