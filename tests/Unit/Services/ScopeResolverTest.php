<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Services;

use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\RoleRepository;
use AuthServer\Models\Client;
use AuthServer\Models\IssuedGrant;
use AuthServer\Models\Realm;
use AuthServer\Models\ScopeRoleMapping;
use AuthServer\Models\User;
use AuthServer\Services\ScopeResolver;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

class ScopeResolverTest extends TestCase
{
    private const USER_ID = 'u-1';
    private const REALM_ID = 'r-id';

    private RoleRepository $roles;
    private ScopeResolver $resolver;
    private Realm $realm;
    private Client $inheritClient;
    private Client $narrowClient;

    protected function setUp(): void
    {
        $this->roles = $this->createMock(RoleRepository::class);

        $this->resolver = new ScopeResolver(new NullLogger(), $this->roles);

        $this->realm = new Realm(
            'r-id', 'test', 'k-id',
            1800, 300, 300, 300, 86400, 1800,
            'openid profile email', '2025-01-01 00:00:00',
        );

        $this->inheritClient = new Client(
            'c-1', 'inherit-app', 'r-id', null, 'https://example.com', false, '2025-01-01 00:00:00',
            null,
        );

        $this->narrowClient = new Client(
            'c-2', 'narrow-app', 'r-id', null, 'https://example.com', false, '2025-01-01 00:00:00',
            'openid profile',
        );
    }

    public function testNullClientScopeInheritsRealm(): void
    {
        $granted = $this->resolver->resolve('openid email', $this->inheritClient, $this->realm, true);
        self::assertSame('openid email', $granted);
    }

    public function testRequestedScopeWithinClientAllowList(): void
    {
        $granted = $this->resolver->resolve('openid profile', $this->narrowClient, $this->realm, true);
        self::assertSame('openid profile', $granted);
    }

    public function testScopeNotInClientAllowListRejected(): void
    {
        $this->expectException(ValidationFailed::class);
        $this->resolver->resolve('openid email', $this->narrowClient, $this->realm, true);
    }

    public function testOpenidAlwaysAllowedEvenIfOmittedFromClientScope(): void
    {
        $client = new Client(
            'c-3', 'openid-less-app', 'r-id', null, 'https://example.com', false, '2025-01-01 00:00:00',
            'profile',
        );
        $granted = $this->resolver->resolve('openid profile', $client, $this->realm, true);
        self::assertSame('openid profile', $granted);
    }

    public function testRequireOpenidMissingOpenidThrows(): void
    {
        $this->expectException(ValidationFailed::class);
        $this->resolver->resolve('profile', $this->inheritClient, $this->realm, true);
    }

    public function testEmptyRequestReturnsEffectiveClientScope(): void
    {
        self::assertSame(
            'openid profile email',
            $this->resolver->resolve('', $this->inheritClient, $this->realm, false)
        );
        self::assertSame(
            'openid profile',
            $this->resolver->resolve('', $this->narrowClient, $this->realm, false)
        );
    }

    public function testScopeInClientButNotInRealmRejected(): void
    {
        $client = new Client(
            'c-4', 'rogue-app', 'r-id', null, 'https://example.com', false, '2025-01-01 00:00:00',
            'openid admin',
        );
        $this->expectException(ValidationFailed::class);
        $this->resolver->resolve('openid admin', $client, $this->realm, true);
    }

    public function testOfflineAccessGatedByClientScope(): void
    {
        $realm = new Realm(
            'r-2', 'test2', 'k-id',
            1800, 300, 300, 300, 86400, 1800,
            'openid profile offline_access', '2025-01-01 00:00:00',
        );
        $client = new Client(
            'c-5', 'web-app', 'r-2', null, 'https://example.com', false, '2025-01-01 00:00:00',
            'openid profile',
        );

        $this->expectException(ValidationFailed::class);
        $this->resolver->resolve('openid offline_access', $client, $realm, true);
    }

    public function testOfflineAccessGrantedWhenClientAllowsIt(): void
    {
        $realm = new Realm(
            'r-3', 'test3', 'k-id',
            1800, 300, 300, 300, 86400, 1800,
            'openid profile offline_access', '2025-01-01 00:00:00',
        );
        $client = new Client(
            'c-6', 'offline-app', 'r-3', null, 'https://example.com', false, '2025-01-01 00:00:00',
            'openid profile offline_access',
        );

        $granted = $this->resolver->resolve('openid offline_access', $client, $realm, true);
        self::assertSame('openid offline_access', $granted);
    }

    public function testClientCredentialsDoesNotRequireOpenid(): void
    {
        $granted = $this->resolver->resolve('profile email', $this->inheritClient, $this->realm, false);
        self::assertSame('profile email', $granted);
    }

    public function testRejectionIsLogged(): void
    {
        $logger = $this->createMock(\Psr\Log\LoggerInterface::class);
        $logger->expects($this->once())
            ->method('info')
            ->with($this->stringContains("scope 'email' not allowed for client 'narrow-app'"));

        $resolver = new ScopeResolver($logger, $this->roles);

        try {
            $resolver->resolve('openid email', $this->narrowClient, $this->realm, true);
            self::fail('expected ValidationFailed');
        } catch (ValidationFailed $e) {
            self::assertSame('invalid scope', $e->getMessage());
        }
    }

    // ── resolveIssuance (F-05 scope↔role mapping) ─────────────

    private function issuanceUser(): User
    {
        return new User(
            self::USER_ID, self::REALM_ID, 'emant',
            'test@example.com', 'hashed', '2025-01-01 00:00:00',
        );
    }

    private function mappedClient(): Client
    {
        return new Client(
            'c-map', 'mapped-app', self::REALM_ID, null,
            'https://example.com', false, '2025-01-01 00:00:00',
        );
    }

    private function stubHeldRoles(array $realmRoles, array $clientRoles): void
    {
        $this->roles->method('findRealmRoleNamesByUserId')->willReturn($realmRoles);
        $this->roles->method('findClientRoleNamesByUserId')->willReturn($clientRoles);
    }

    /**
     * @param array<string, list<ScopeRoleMapping>> $mappings
     * @param array<string, list<string>> $clientRoles
     */
    private function issueWith(
        array $mappings,
        array $realmRoles,
        array $clientRoles,
        string $scope
    ): IssuedGrant {
        $this->roles->method('findScopeRoleMappings')->willReturn($mappings);
        $this->stubHeldRoles($realmRoles, $clientRoles);

        return $this->resolver->resolveIssuance(
            $scope,
            $this->issuanceUser(),
            $this->mappedClient()
        );
    }

    public function testIssuanceWithoutMappingsFallsBackToFullScope(): void
    {
        $issued = $this->issueWith([], ['basic', 'admin'], ['mapped-app' => ['app-user']], 'openid profile');

        self::assertSame('openid profile', $issued->scope);
        self::assertSame(['basic', 'admin'], $issued->roleClaims->realmRoles);
        self::assertSame(['mapped-app' => ['roles' => ['app-user']]], $issued->roleClaims->resourceAccess);
    }

    public function testScopeWithRequiredRoleMissingIsDropped(): void
    {
        $issued = $this->issueWith(
            ['admin' => [new ScopeRoleMapping('role-admin', 'admin', 'admin', null, true)]],
            ['basic'],
            [],
            'openid profile admin'
        );

        self::assertSame('openid profile', $issued->scope);
        self::assertSame([], $issued->roleClaims->realmRoles);
        self::assertNull($issued->roleClaims->resourceAccess);
    }

    public function testScopeWithRequiredRoleHeldIsKeptAndRoleIncluded(): void
    {
        $issued = $this->issueWith(
            ['admin' => [new ScopeRoleMapping('role-admin', 'admin', 'admin', null, true)]],
            ['basic', 'admin'],
            [],
            'openid admin'
        );

        self::assertSame('openid admin', $issued->scope);
        self::assertSame(['admin'], $issued->roleClaims->realmRoles);
    }

    /**
     * @return list<ScopeRoleMapping>
     */
    private function profileMapping(): array
    {
        return [new ScopeRoleMapping('role-app-user', 'profile', 'app-user', 'mapped-app', false)];
    }

    public function testIncludeMappingRoleNotHeldIsSkipped(): void
    {
        $issued = $this->issueWith(['profile' => $this->profileMapping()], ['basic'], [], 'openid profile');

        self::assertSame('openid profile', $issued->scope);
        self::assertNull($issued->roleClaims->resourceAccess);
    }

    public function testIncludeMappingHeldRoleIsEmittedUnderClientNamespace(): void
    {
        $issued = $this->issueWith(
            ['profile' => $this->profileMapping()],
            ['basic'],
            ['mapped-app' => ['app-user']],
            'openid profile'
        );

        self::assertSame('openid profile', $issued->scope);
        self::assertSame(['mapped-app' => ['roles' => ['app-user']]], $issued->roleClaims->resourceAccess);
    }

    public function testUnmappedScopesPassThroughUntouchedInRestrictedMode(): void
    {
        $issued = $this->issueWith(
            ['admin' => [new ScopeRoleMapping('role-admin', 'admin', 'admin', null, true)]],
            [],
            [],
            'openid'
        );

        self::assertSame('openid', $issued->scope);
        self::assertSame([], $issued->roleClaims->realmRoles);
    }

    public function testClientRoleOfAnotherNamespaceIsNotEmittedForResourceAccess(): void
    {
        $this->roles->method('findScopeRoleMappings')->willReturn([
            'profile' => [new ScopeRoleMapping('role-other', 'profile', 'other-role', 'other-app', false)],
        ]);
        $this->stubHeldRoles([], ['other-app' => ['other-role']]);

        $issued = $this->resolver->resolveIssuance(
            'openid profile',
            $this->issuanceUser(),
            $this->mappedClient()
        );

        self::assertNull($issued->roleClaims->resourceAccess);
    }

    public function testSplitScopeFiltersEmptyStrings(): void
    {
        $granted = $this->resolver->resolve('openid  profile', $this->inheritClient, $this->realm, true);
        self::assertSame('openid profile', $granted);
    }
}
