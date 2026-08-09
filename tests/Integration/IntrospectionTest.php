<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Tests\Support\IntegrationFlowTrait;
use AuthServer\Tests\Support\TestAppFactory;
use PHPUnit\Framework\TestCase;

class IntrospectionTest extends TestCase
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