<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Services\TokenService;
use AuthServer\Tests\Support\IntegrationFlowTrait;
use AuthServer\Tests\Support\TestAppFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

class OfflineAccessTest extends TestCase
{
    use IntegrationFlowTrait;

    private const OFFLINE_TTL = 2592000;
    private const LOCAL_CLIENT_ID = 'a540c566-dfbf-430a-9941-fb8531c022d4';

    private static \Slim\App $app;
    private static \PDO $pdo;
    private static TokenService $tokenService;
    private static \AuthServer\Services\InMemorySessionCookieHandler $sessionCookieHandler;

    public static function setUpBeforeClass(): void
    {
        self::$app = TestAppFactory::createApp();
        self::$pdo = self::$app->getContainer()->get(\PDO::class);
        self::$tokenService = self::$app->getContainer()->get(TokenService::class);
        self::$sessionCookieHandler = self::$app->getContainer()->get(
            \AuthServer\Interfaces\SessionCookieHandler::class
        );

        // Grant offline_access in the 'test' realm (client 'local' inherits the
        // realm scope because its own scope column is NULL). This is done here,
        // not in the seed, so realm-wide discovery defaults stay untouched.
        self::$pdo->exec(
            "UPDATE realms SET scope = 'openid profile email offline_access' WHERE name = 'test'"
        );
    }

    protected function setUp(): void
    {
        self::$sessionCookieHandler->reset();
    }

    // ── Flow helpers ──────────────────────────────────────────

    private function offlineLogin(
        string $clientId = 'local',
        string $redirectUri = 'http://localhost:5173'
    ): array {
        $code = $this->obtainCode(
            'of-st',
            'of-nc',
            clientId: $clientId,
            redirectUri: $redirectUri,
            scope: 'openid offline_access'
        );
        $response = $this->redeemCode($code, $clientId, $redirectUri);
        self::assertSame(200, $response->getStatusCode(), 'offline code redemption should succeed');
        return json_decode((string) $response->getBody(), true);
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

    private function assertRefreshRejected(string $refreshToken, string $clientId = 'local'): void
    {
        $response = $this->refresh($refreshToken, $clientId);
        self::assertSame(400, $response->getStatusCode());
    }

    private function assertRefreshSucceeds(string $refreshToken): array
    {
        $response = $this->refresh($refreshToken);
        self::assertSame(200, $response->getStatusCode());
        return json_decode((string) $response->getBody(), true);
    }

    private function revoke(string $token, string $clientId = 'local', ?string $hint = null): ResponseInterface
    {
        $body = ['token' => $token, 'client_id' => $clientId];
        if ($hint !== null) {
            $body['token_type_hint'] = $hint;
        }
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/revoke', [], $body);
        return $this->handle($request);
    }

    private function introspect(string $token, string $clientId = 'local'): array
    {
        $request = $this->createRequest('POST', '/realms/test/protocol/openid-connect/token/introspect', [], [
            'token' => $token,
            'client_id' => $clientId,
        ]);
        $response = $this->handle($request);
        self::assertSame(200, $response->getStatusCode());
        return json_decode((string) $response->getBody(), true);
    }

    private function logout(string $idToken): ResponseInterface
    {
        $request = $this->createRequest(
            'GET',
            '/realms/test/protocol/openid-connect/logout',
            ['id_token_hint' => $idToken]
        );
        return $this->handle($request);
    }

    private function expireAllSsoSessions(): void
    {
        self::$pdo->exec("UPDATE sessions SET status = 'EXPIRED'");
    }

    // ── Offline grant creation ────────────────────────────────

    public function testOfflineLoginIssuesOfflineRefreshToken(): void
    {
        $tokens = $this->offlineLogin();

        self::assertSame(self::OFFLINE_TTL, $tokens['refresh_expires_in']);
        self::assertSame('openid offline_access', $tokens['scope']);

        $refresh = self::$tokenService->decodeTokenPayload($tokens['refresh_token']);
        self::assertSame('Offline', $refresh['typ']);
        self::assertSame($tokens['session_state'], $refresh['sid']);
        self::assertSame(self::OFFLINE_TTL, $refresh['exp'] - $refresh['iat']);
        self::assertSame('openid offline_access', $refresh['scope']);

        $access = self::$tokenService->decodeTokenPayload($tokens['access_token']);
        self::assertSame('Bearer', $access['typ']);
        self::assertSame($tokens['session_state'], $access['sid']);

        // The SSO-bound `logins` row is left alone: no refresh token stored
        $loginRefreshToken = self::$pdo->query(
            "SELECT refresh_token FROM logins WHERE client_id = '" . self::LOCAL_CLIENT_ID . "'"
        )->fetchColumn();
        self::assertNull($loginRefreshToken);
    }

    // ── Offline refresh ───────────────────────────────────────

    public function testOfflineRefreshRotatesToken(): void
    {
        $tokens = $this->offlineLogin();

        $newTokens = $this->assertRefreshSucceeds($tokens['refresh_token']);
        self::assertSame(self::OFFLINE_TTL, $newTokens['refresh_expires_in']);
        self::assertSame('openid offline_access', $newTokens['scope']);
        self::assertNotSame($tokens['refresh_token'], $newTokens['refresh_token']);

        // Rotation: the old token is dead, the new one works
        $this->assertRefreshRejected($tokens['refresh_token']);
        $this->assertRefreshSucceeds($newTokens['refresh_token']);
    }

    public function testOfflineRefreshSurvivesLogout(): void
    {
        $tokens = $this->offlineLogin();

        $response = $this->logout($tokens['id_token']);
        self::assertSame(204, $response->getStatusCode());

        $this->assertRefreshSucceeds($tokens['refresh_token']);
    }

    public function testOfflineRefreshSurvivesExpiredSsoSession(): void
    {
        $tokens = $this->offlineLogin();

        $this->expireAllSsoSessions();

        $this->assertRefreshSucceeds($tokens['refresh_token']);
    }

    public function testOfflineRefreshDoesNotWidenScope(): void
    {
        $tokens = $this->offlineLogin();

        $newTokens = $this->assertRefreshSucceeds($tokens['refresh_token']);

        $access = self::$tokenService->decodeTokenPayload($newTokens['access_token']);
        self::assertSame('openid offline_access', $access['scope']);
    }

    public function testCrossClientOfflineRefreshRejected(): void
    {
        $tokens = $this->offlineLogin();

        $this->assertRefreshRejected($tokens['refresh_token'], 'kc_app');

        // The failed attempt must not expire or rotate the offline session
        $this->assertRefreshSucceeds($tokens['refresh_token']);
    }

    public function testNonOfflineRefreshRemainsBoundToSsoSession(): void
    {
        $tokens = $this->doFullLogin();

        // Works while the SSO session lives
        $this->assertRefreshSucceeds($tokens['refresh_token']);

        // Logout kills the SSO session, and with it the plain refresh token
        $response = $this->logout($tokens['id_token']);
        self::assertSame(204, $response->getStatusCode());

        $this->assertRefreshRejected($tokens['refresh_token']);
    }

    // ── Revocation ────────────────────────────────────────────

    public function testRevokeOfflineToken(): void
    {
        $tokens = $this->offlineLogin();

        $response = $this->revoke($tokens['refresh_token']);
        self::assertSame(200, $response->getStatusCode());

        $this->assertRefreshRejected($tokens['refresh_token']);
        self::assertFalse($this->introspect($tokens['refresh_token'])['active']);
    }

    // ── Introspection ─────────────────────────────────────────

    public function testIntrospectOfflineToken(): void
    {
        $tokens = $this->offlineLogin();

        $body = $this->introspect($tokens['refresh_token']);
        self::assertTrue($body['active']);
        self::assertSame('refresh_token', $body['token_type']);
        // Refresh-token introspection reports the client id, matching the
        // existing online refresh-token introspection behavior
        self::assertSame(self::LOCAL_CLIENT_ID, $body['client_id']);
        self::assertSame('openid offline_access', $body['scope']);
        self::assertSame($tokens['session_state'], $body['sid']);
    }

    public function testIntrospectOfflineAccessToken(): void
    {
        $tokens = $this->offlineLogin();

        $body = $this->introspect($tokens['access_token']);
        self::assertTrue($body['active']);
        self::assertSame('Bearer', $body['token_type']);
    }
}
