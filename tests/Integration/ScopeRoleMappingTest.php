<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Interfaces\SessionCookieHandler;
use AuthServer\Services\Base64Utils;
use AuthServer\Services\InMemorySessionCookieHandler;
use AuthServer\Tests\Support\IntegrationFlowTrait;
use AuthServer\Tests\Support\TestAppFactory;
use PHPUnit\Framework\TestCase;

/**
 * F-05 — scope↔role mapping at issuance: a client with role scope mappings
 * emits only the mapped roles the user holds and drops scopes whose required
 * role is missing; clients without mappings keep full-scope behaviour.
 */
class ScopeRoleMappingTest extends TestCase
{
    use IntegrationFlowTrait;

    private const KC_APP_ID = 'df616379-3695-4466-bcda-910fcb50bb01';
    private const ADMIN_ROLE_TEST_REALM = '5a1a1000-0000-4000-8000-000000000004';
    private const APP_USER_ROLE = '5a1a1000-0000-4000-8000-000000000005';
    private const EMANT_TEST_ID = 'b0aa0c22-a356-40c7-9fa2-6f973c3f614a';

    private static \Slim\App $app;
    private static \PDO $pdo;

    public static function setUpBeforeClass(): void
    {
        self::$app = TestAppFactory::createApp();
        self::$pdo = self::$app->getContainer()->get(\PDO::class);

        // 'admin' must be a requestable scope in the realm for this suite.
        self::$pdo->exec(
            "UPDATE realms SET scope = 'openid profile email admin' WHERE name = 'test'"
        );

        self::insertMapping('admin', self::ADMIN_ROLE_TEST_REALM, 1);
        self::insertMapping('profile', self::APP_USER_ROLE, 0);

        // emant_test loses her admin realm role for the non-admin scenarios.
        self::$pdo->prepare(
            'DELETE FROM user_role_assignments WHERE user_id = :u AND role_id = :r'
        )->execute([':u' => self::EMANT_TEST_ID, ':r' => self::ADMIN_ROLE_TEST_REALM]);
    }

    private static function insertMapping(string $scope, string $roleId, int $required): void
    {
        $stmt = self::$pdo->prepare(
            'INSERT OR IGNORE INTO client_scope_roles (client_id, scope, role_id, required)
             VALUES (:client_id, :scope, :role_id, :required)'
        );
        $stmt->execute([
            ':client_id' => self::KC_APP_ID,
            ':scope' => $scope,
            ':role_id' => $roleId,
            ':required' => $required,
        ]);
    }

    private static function assignRole(string $userId, string $roleId): void
    {
        self::$pdo->prepare(
            'INSERT OR IGNORE INTO user_role_assignments (user_id, role_id) VALUES (:u, :r)'
        )->execute([':u' => $userId, ':r' => $roleId]);
    }

    private static function unassignRole(string $userId, string $roleId): void
    {
        self::$pdo->prepare(
            'DELETE FROM user_role_assignments WHERE user_id = :u AND role_id = :r'
        )->execute([':u' => $userId, ':r' => $roleId]);
    }

    public function setUp(): void
    {
        $handler = self::$app->getContainer()->get(SessionCookieHandler::class);
        if ($handler instanceof InMemorySessionCookieHandler) {
            $handler->reset();
        }
    }

    /**
     * @return array{scope: string, payload: array<string, mixed>}
     */
    private function issueTokens(string $scope): array
    {
        $code = $this->obtainCode(
            uniqid('srm-st'),
            uniqid('srm-nc'),
            'kc_app',
            'https://www.keycloak.org/app',
            $scope
        );
        $response = $this->redeemCode($code, 'kc_app', 'https://www.keycloak.org/app');
        self::assertSame(200, $response->getStatusCode());

        $bundle = json_decode((string) $response->getBody(), true);
        return [
            'scope' => $bundle['scope'],
            'payload' => json_decode(
                Base64Utils::b64UrlDecode(explode('.', $bundle['access_token'])[1]),
                true
            ),
        ];
    }

    public function testScopeWithRequiredRoleMissingIsDroppedAtIssuance(): void
    {
        $issued = $this->issueTokens('openid profile admin');

        self::assertSame('openid profile', $issued['scope']);
        self::assertSame('openid profile', $issued['payload']['scope']);
        self::assertSame([], $issued['payload']['realm_access']['roles']);
    }

    public function testAdminUserKeepsScopeAndGetsMappedRealmRole(): void
    {
        self::assignRole(self::EMANT_TEST_ID, self::ADMIN_ROLE_TEST_REALM);

        try {
            $issued = $this->issueTokens('openid profile admin');

            self::assertSame('openid profile admin', $issued['scope']);
            self::assertContains('admin', $issued['payload']['realm_access']['roles']);
        } finally {
            self::unassignRole(self::EMANT_TEST_ID, self::ADMIN_ROLE_TEST_REALM);
        }
    }

    public function testMappedClientRoleEmittedOnlyForTheTokenClient(): void
    {
        $issued = $this->issueTokens('openid profile');

        self::assertSame(
            ['kc_app' => ['roles' => ['app-user']]],
            $issued['payload']['resource_access']
        );
    }

    public function testRefreshReDerivesAndNeverWidens(): void
    {
        self::assignRole(self::EMANT_TEST_ID, self::ADMIN_ROLE_TEST_REALM);

        try {
            $code = $this->obtainCode(
            uniqid('srm-rf'),
            uniqid('srm-rf-n'),
            'kc_app',
            'https://www.keycloak.org/app',
            'openid profile admin'
        );
            $response = $this->redeemCode($code, 'kc_app', 'https://www.keycloak.org/app');
            $bundle = json_decode((string) $response->getBody(), true);
            self::assertSame('openid profile admin', $bundle['scope']);

            // The admin role disappears between issuance and refresh.
            self::unassignRole(self::EMANT_TEST_ID, self::ADMIN_ROLE_TEST_REALM);

            $request = $this->createRequest(
                'POST',
                '/realms/test/protocol/openid-connect/token',
                [],
                [
                    'grant_type' => 'refresh_token',
                    'client_id' => 'kc_app',
                    'refresh_token' => $bundle['refresh_token'],
                ]
            );
            $response = $this->handle($request);
            self::assertSame(200, $response->getStatusCode());
            $refreshed = json_decode((string) $response->getBody(), true);

            self::assertSame('openid profile', $refreshed['scope']);
            $payload = json_decode(
                Base64Utils::b64UrlDecode(explode('.', $refreshed['access_token'])[1]),
                true
            );
            self::assertNotContains('admin', $payload['realm_access']['roles']);
        } finally {
            self::unassignRole(self::EMANT_TEST_ID, self::ADMIN_ROLE_TEST_REALM);
        }
    }

    public function testClientWithoutMappingsKeepsFullScopeBehaviour(): void
    {
        self::assignRole(self::EMANT_TEST_ID, self::ADMIN_ROLE_TEST_REALM);

        try {
            $bundle = $this->doFullLogin(clientId: 'local');

            $payload = json_decode(
                Base64Utils::b64UrlDecode(explode('.', $bundle['access_token'])[1]),
                true
            );
            self::assertSame(['admin', 'basic'], $payload['realm_access']['roles']);
            self::assertArrayNotHasKey('resource_access', $payload);
        } finally {
            self::unassignRole(self::EMANT_TEST_ID, self::ADMIN_ROLE_TEST_REALM);
        }
    }
}
