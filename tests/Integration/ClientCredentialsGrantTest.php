<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Tests\Support\IntegrationFlowTrait;
use AuthServer\Tests\Support\TestAppFactory;
use PHPUnit\Framework\TestCase;

class ClientCredentialsGrantTest extends TestCase
{
    use IntegrationFlowTrait;
    private static \Slim\App $app;
    private static \PDO $pdo;

    public static function setUpBeforeClass(): void
    {
        self::$app = TestAppFactory::createApp();
        self::$pdo = self::$app->getContainer()->get(\PDO::class);

        // Add a confidential client (require_auth=1) for secret-validation tests.
        $secretHash = '$argon2id$v=19$m=1024,t=2,p=2$YUM1NlEwLkxBS09xbGJWQw$bGDwvY/HzVl7SsOsGhgYwQkwB4QCamL/SU2EjzOtd2o';
        $stmt = self::$pdo->prepare(
            "INSERT INTO clients (id, name, realm_id, client_secret, uri, require_auth)
             VALUES (:id, :name, :realm, :secret, :uri, 1)"
        );
        $stmt->execute([
            ':id' => '3f8d4a11-9c2e-4b6d-8a1f-9d2c1e4b5a6b',
            ':name' => 'svc',
            ':realm' => 'c03aa58c-2888-4f40-821c-4aadf5c58f6f',
            ':secret' => $secretHash,
            ':uri' => 'http://localhost:5173',
        ]);
    }

    private function grantClientCredentials(array $params): array
    {
        $request = $this->createRequest(
            'POST',
            '/realms/test/protocol/openid-connect/token',
            [],
            $params
        );
        $response = $this->handle($request);
        return [$response, json_decode((string) $response->getBody(), true)];
    }

    // ── Well-known ─────────────────────────────────────────────

    public function testWellKnownAdvertisesClientCredentialsGrant(): void
    {
        $request = $this->createRequest('GET', '/realms/test/.well-known/openid-configuration');
        $response = $this->handle($request);

        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        self::assertContains('client_credentials', $body['grant_types_supported']);
    }

    // ── Grant success ──────────────────────────────────────────

    public function testClientCredentialsIssuesAccessTokenOnly(): void
    {
        [$response, $body] = $this->grantClientCredentials([
            'grant_type' => 'client_credentials',
            'client_id' => 'local',
        ]);

        self::assertSame(200, $response->getStatusCode());
        self::assertNotEmpty($body['access_token']);
        self::assertSame('Bearer', $body['token_type']);
        self::assertArrayNotHasKey('refresh_token', $body);
        self::assertArrayNotHasKey('id_token', $body);
        self::assertSame('openid profile email', $body['scope']);
    }

    public function testClientCredentialsWithExplicitScope(): void
    {
        [$response, $body] = $this->grantClientCredentials([
            'grant_type' => 'client_credentials',
            'client_id' => 'local',
            'scope' => 'openid',
        ]);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('openid', $body['scope']);
    }

    public function testClientCredentialsTokenCarriesExpectedClaims(): void
    {
        [$response, $body] = $this->grantClientCredentials([
            'grant_type' => 'client_credentials',
            'client_id' => 'local',
        ]);

        self::assertSame(200, $response->getStatusCode());
        $payload = json_decode(
            base64_decode(str_replace(
                ['-', '_'],
                ['+', '/'],
                explode('.', $body['access_token'])[1]
            )),
            true
        );
        self::assertSame('Bearer', $payload['typ']);
        self::assertSame('local', $payload['sub']);
        self::assertSame('local', $payload['azp']);
        self::assertSame('local', $payload['aud']);
        self::assertArrayNotHasKey('session_state', $payload);
        self::assertArrayNotHasKey('sid', $payload);
    }

    // ── Grant failures ─────────────────────────────────────────

    public function testClientCredentialsRejectsUnknownScope(): void
    {
        [$response] = $this->grantClientCredentials([
            'grant_type' => 'client_credentials',
            'client_id' => 'local',
            'scope' => 'bogus',
        ]);

        self::assertSame(400, $response->getStatusCode());
    }

    public function testClientCredentialsRejectsUnknownClient(): void
    {
        [$response] = $this->grantClientCredentials([
            'grant_type' => 'client_credentials',
            'client_id' => 'does-not-exist',
        ]);

        self::assertSame(401, $response->getStatusCode());
    }

    public function testClientCredentialsRejectsUnsupportedGrantType(): void
    {
        [$response] = $this->grantClientCredentials([
            'grant_type' => 'implicit',
            'client_id' => 'local',
        ]);

        self::assertSame(400, $response->getStatusCode());
    }

    public function testClientCredentialsWithoutClientIdRejected(): void
    {
        [$response] = $this->grantClientCredentials([
            'grant_type' => 'client_credentials',
        ]);

        self::assertSame(400, $response->getStatusCode());
    }

    public function testClientCredentialsRequiresSecretWhenClientIsConfidential(): void
    {
        // Wrong secret
        [$response] = $this->grantClientCredentials([
            'grant_type' => 'client_credentials',
            'client_id' => 'svc',
            'client_secret' => 'wrong-secret',
        ]);
        self::assertSame(401, $response->getStatusCode());

        // Correct secret
        [$response, $body] = $this->grantClientCredentials([
            'grant_type' => 'client_credentials',
            'client_id' => 'svc',
            'client_secret' => 'c_id',
        ]);
        self::assertSame(200, $response->getStatusCode());
        self::assertNotEmpty($body['access_token']);
    }

    // ── Lifecycle (introspect / revoke) ────────────────────────

    public function testClientCredentialsTokenIntrospectsAsActive(): void
    {
        [, $tokens] = $this->grantClientCredentials([
            'grant_type' => 'client_credentials',
            'client_id' => 'local',
        ]);

        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token/introspect', [], [
            'token' => $tokens['access_token'],
            'client_id' => 'local',
        ]);
        $response = $this->handle($request);
        $body = json_decode((string) $response->getBody(), true);

        self::assertTrue($body['active']);
        self::assertSame('local', $body['client_id']);
        self::assertSame('local', $body['sub']);
        self::assertSame('Bearer', $body['token_type']);
    }

    public function testClientCredentialsTokenCanBeRevoked(): void
    {
        [, $tokens] = $this->grantClientCredentials([
            'grant_type' => 'client_credentials',
            'client_id' => 'local',
        ]);

        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/revoke', [], [
            'token' => $tokens['access_token'],
            'token_type_hint' => 'access_token',
            'client_id' => 'local',
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());

        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token/introspect', [], [
            'token' => $tokens['access_token'],
            'client_id' => 'local',
        ]);
        $response = $this->handle($request);
        $body = json_decode((string) $response->getBody(), true);
        self::assertFalse($body['active']);
    }
}
