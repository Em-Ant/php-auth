<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration\Repositories;

use AuthServer\Models\Role;
use AuthServer\Repositories\RoleRepository;
use AuthServer\Tests\Integration\RepositoryTestCase;
use AuthServer\Tests\Support\RealmFixture;

class RoleRepositoryTest extends RepositoryTestCase
{
    private const WEB_REALM = '84be68b8-7936-4422-bb4d-b741d2292a9f';
    private const TEST_REALM = 'c03aa58c-2888-4f40-821c-4aadf5c58f6f';
    private const EMANT = '586d7bb3-d386-4b57-9e99-b2a460f20b47';
    private const EMANT_TEST = 'b0aa0c22-a356-40c7-9fa2-6f973c3f614a';
    private const KC_APP = 'df616379-3695-4466-bcda-910fcb50bb01';

    private RoleRepository $repo;

    protected function setUp(): void
    {
        $this->repo = new RoleRepository(self::$pdo);
    }

    public function testFindRealmRoleNamesByUserIdReturnsSeededRoles(): void
    {
        self::assertSame(
            ['admin', 'basic'],
            $this->repo->findRealmRoleNamesByUserId(self::EMANT, self::WEB_REALM)
        );
    }

    public function testFindRealmRoleNamesByUserIdIgnoresOtherRealms(): void
    {
        self::assertSame(
            [],
            $this->repo->findRealmRoleNamesByUserId(self::EMANT, self::TEST_REALM)
        );
    }

    public function testFindClientRoleNamesByUserIdGroupsRolesByClient(): void
    {
        $roles = $this->repo->findClientRoleNamesByUserId(self::EMANT_TEST, self::TEST_REALM);

        self::assertSame(['kc_app' => ['app-user']], $roles);
        self::assertSame([], $this->repo->findClientRoleNamesByUserId(self::EMANT, self::WEB_REALM));
    }

    public function testSyncRealmRolesReplacesAssignmentsAndCreatesMissingRoles(): void
    {
        $this->repo->syncRealmRoles(self::EMANT_TEST, self::TEST_REALM, ['basic', 'manager']);

        self::assertSame(
            ['basic', 'manager'],
            $this->repo->findRealmRoleNamesByUserId(self::EMANT_TEST, self::TEST_REALM)
        );
    }

    public function testSyncRealmRolesPreservesClientRoleAssignments(): void
    {
        $this->repo->syncRealmRoles(self::EMANT_TEST, self::TEST_REALM, ['basic']);

        self::assertSame(
            ['kc_app' => ['app-user']],
            $this->repo->findClientRoleNamesByUserId(self::EMANT_TEST, self::TEST_REALM)
        );
    }

    public function testSyncRealmRolesToEmptyClearsRealmAssignmentsOnly(): void
    {
        $this->repo->syncRealmRoles(self::EMANT_TEST, self::TEST_REALM, []);

        self::assertSame(
            [],
            $this->repo->findRealmRoleNamesByUserId(self::EMANT_TEST, self::TEST_REALM)
        );
        self::assertNotSame(
            [],
            $this->repo->findClientRoleNamesByUserId(self::EMANT_TEST, self::TEST_REALM)
        );
    }

    public function testSyncRealmRolesJoinsCallerTransaction(): void
    {
        self::$pdo->beginTransaction();
        $this->repo->syncRealmRoles(self::EMANT_TEST, self::TEST_REALM, ['joined']);
        self::$pdo->commit();

        self::assertSame(
            ['joined'],
            $this->repo->findRealmRoleNamesByUserId(self::EMANT_TEST, self::TEST_REALM)
        );
    }

    public function testCreateAndFindByIdRoundTripForRealmRole(): void
    {
        $role = $this->repo->create($this->role(null, 'auditor'));
        $loaded = $this->repo->findById($role->getId());

        self::assertNotNull($loaded);
        self::assertSame('auditor', $loaded->getName());
        self::assertTrue($loaded->isRealmRole());
        self::assertFalse($loaded->isClientRole());
        self::assertSame(self::TEST_REALM, $loaded->getRealmId());
    }

    public function testCreateAndFindByIdRoundTripForClientRole(): void
    {
        $role = $this->repo->create($this->role(self::KC_APP, 'app-auditor', 'can audit'));
        $loaded = $this->repo->findById($role->getId());

        self::assertNotNull($loaded);
        self::assertTrue($loaded->isClientRole());
        self::assertSame(self::KC_APP, $loaded->getClientId());
        self::assertSame('can audit', $loaded->getDescription());
    }

    public function testDeleteRemovesRole(): void
    {
        $role = $this->repo->create($this->role(null, 'doomed'));

        self::assertTrue($this->repo->delete($role->getId()));
        self::assertNull($this->repo->findById($role->getId()));
    }

    public function testDeleteUnknownRoleReturnsFalse(): void
    {
        self::assertFalse($this->repo->delete('nonexistent'));
    }

    public function testFindAllFiltersByRealmAndClient(): void
    {
        $realmId = '9a1a1000-0000-4000-8000-0000000000f1';
        $clientId = '9a1a1000-0000-4000-8000-0000000000f2';
        $otherClientId = '9a1a1000-0000-4000-8000-0000000000f3';

        RealmFixture::createRealm(self::$pdo, $realmId, 'roles-findall');
        RealmFixture::createClient(self::$pdo, $clientId, 'fa_client', $realmId);
        RealmFixture::createClient(self::$pdo, $otherClientId, 'fb_client', $realmId);

        $this->repo->create(new Role('', $realmId, null, 'zeta', null, new \DateTime()));
        $this->repo->create(new Role('', $realmId, $clientId, 'alpha', null, new \DateTime()));
        $this->repo->create(new Role('', $realmId, $otherClientId, 'omega', null, new \DateTime()));

        $allInRealm = array_map(
            fn(Role $r) => $r->getName(),
            $this->repo->findAll($realmId)
        );
        self::assertSame(['alpha', 'omega', 'zeta'], $allInRealm);

        $onlyClient = array_map(
            fn(Role $r) => $r->getName(),
            $this->repo->findAll($realmId, $clientId)
        );
        self::assertSame(['alpha'], $onlyClient);
    }

    private function role(?string $clientId, string $name, ?string $description = null): Role
    {
        return new Role(
            '',
            self::TEST_REALM,
            $clientId,
            $name,
            $description,
            new \DateTime('2025-01-01 00:00:00', new \DateTimeZone('UTC')),
        );
    }
}
