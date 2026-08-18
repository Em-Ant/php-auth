<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Tests\Support\IntegrationFlowTrait;
use AuthServer\Tests\Support\TestAppFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

class CodeBindingTest extends TestCase
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

    private function redeemCode(string $code, string $clientId, string $redirectUri): ResponseInterface
    {
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token', [], [
            'grant_type' => 'authorization_code',
            'client_id' => $clientId,
            'code' => $code,
            'redirect_uri' => $redirectUri,
        ]);
        return $this->handle($request);
    }

    private function assertInvalidGrant(ResponseInterface $response): void
    {
        self::assertSame(400, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertSame('invalid_grant', $body['error_description'] ?? null);
    }

    private function assertCodeRedeems(string $code, string $clientId, string $redirectUri): void
    {
        $tokens = json_decode((string) $this->redeemCode($code, $clientId, $redirectUri)->getBody(), true);
        self::assertNotNull($tokens['access_token'] ?? null);
    }

    public function testCodeBoundToIssuingClientRejectedByAnotherClient(): void
    {
        $code = $this->obtainCode(
            state: 'cb-client-st',
            nonce: 'cb-client-nc',
            clientId: 'kc_app',
            redirectUri: 'https://www.keycloak.org/app',
        );

        $response = $this->redeemCode($code, 'local', 'http://localhost:5173');
        $this->assertInvalidGrant($response);

        $this->assertCodeRedeems($code, 'kc_app', 'https://www.keycloak.org/app');
    }

    public function testCodeBoundToRedirectUriRejectedByDifferentRedirect(): void
    {
        $code = $this->obtainCode(
            state: 'cb-redir-st',
            nonce: 'cb-redir-nc',
        );

        $response = $this->redeemCode($code, 'local', 'http://localhost:5173/cb');
        $this->assertInvalidGrant($response);

        $this->assertCodeRedeems($code, 'local', 'http://localhost:5173');
    }
}
