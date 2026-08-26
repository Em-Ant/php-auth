<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Tests\Support\AdminApiTrait;
use AuthServer\Tests\Support\TestAppFactory;
use PHPUnit\Framework\TestCase;

use function AuthServer\getGuid;

class AdminRolesTest extends TestCase
{
    use AdminApiTrait;

    private const TEST_REALM = 'c03aa58c-2888-4f40-821c-4aadf5c58f6f';
    private const KC_APP_CLIENT = 'df616379-3695-4466-bcda-910fcb50bb01';
    private const TEST_USER = 'b0aa0c22-a356-40c7-9fa2-6f973c3f614a';
    private const BASIC_ROLE = '5a1a1000-0000-4000-8000-000000000003';
    private const ADMIN_ROLE = '5a1a1000-0000-4000-8000-000000000004';

    private static \Slim\App $app;
    private static \PDO $pdo;
    private static string $adminKey = 'test-admin-key';

    public static function setUpBeforeClass(): void
    {
        self::$app = TestAppFactory::createApp([
            'admin_api_key' => self::$adminKey,
        ]);
        self::$pdo = self::$app->getContainer()->get(\PDO::class);
    }

    // ── Roles CRUD ──────────────────────────────────────────

    public function testListRolesReturnsSeededRoles(): void
    {
        $data = $this->assertStatus(200, $this->adminRequest('GET', '/admin/roles'));

        self::assertArrayHasKey('items', $data);
        self::assertGreaterThan(0, $data['total']);
        $names = array_column($data['items'], 'name');
        self::assertContains('basic', $names);
        self::assertContains('admin', $names);
    }

    public function testListRolesFilteredByRealm(): void
    {
        $data = $this->assertStatus(200, $this->adminRequest(
            'GET',
            '/admin/roles',
            [],
            ['realm_id' => self::TEST_REALM]
        ));

        self::assertArrayHasKey('items', $data);
        foreach ($data['items'] as $role) {
            self::assertSame(self::TEST_REALM, $role['realm_id']);
        }
    }

    public function testListRolesFilteredByClient(): void
    {
        $data = $this->assertStatus(200, $this->adminRequest(
            'GET',
            '/admin/roles',
            [],
            ['client_id' => self::KC_APP_CLIENT]
        ));

        self::assertArrayHasKey('items', $data);
        foreach ($data['items'] as $role) {
            self::assertSame(self::KC_APP_CLIENT, $role['client_id']);
        }
    }

    public function testCreateRole(): void
    {
        $data = $this->assertStatus(201, $this->adminRequest('POST', '/admin/roles', [
            'name' => 'editor',
            'realm_id' => self::TEST_REALM,
            'description' => 'Can edit content',
        ]));

        self::assertArrayHasKey('id', $data);
        self::assertSame('editor', $data['name']);
        self::assertSame(self::TEST_REALM, $data['realm_id']);
        self::assertNull($data['client_id']);
        self::assertSame('Can edit content', $data['description']);
    }

    public function testCreateClientRole(): void
    {
        $data = $this->assertStatus(201, $this->adminRequest('POST', '/admin/roles', [
            'name' => 'viewer',
            'realm_id' => self::TEST_REALM,
            'client_id' => self::KC_APP_CLIENT,
        ]));

        self::assertSame('viewer', $data['name']);
        self::assertSame(self::KC_APP_CLIENT, $data['client_id']);
    }

    public function testCreateRoleDuplicateReturns409(): void
    {
        $this->assertStatus(409, $this->adminRequest('POST', '/admin/roles', [
            'name' => 'basic',
            'realm_id' => self::TEST_REALM,
        ]));
    }

    public function testCreateRoleMissingNameReturns400(): void
    {
        $this->assertStatus(400, $this->adminRequest('POST', '/admin/roles', [
            'realm_id' => self::TEST_REALM,
        ]));
    }

    public function testCreateRoleUnknownRealmReturns400(): void
    {
        $this->assertStatus(400, $this->adminRequest('POST', '/admin/roles', [
            'name' => 'test-role',
            'realm_id' => getGuid(),
        ]));
    }

    public function testReadRole(): void
    {
        $data = $this->assertStatus(200, $this->adminRequest(
            'GET',
            "/admin/roles/" . self::BASIC_ROLE
        ));

        self::assertSame(self::BASIC_ROLE, $data['id']);
        self::assertSame('basic', $data['name']);
    }

    public function testReadRoleNotFound(): void
    {
        $this->assertStatus(404, $this->adminRequest(
            'GET',
            '/admin/roles/' . getGuid()
        ));
    }

    public function testUpdateRole(): void
    {
        $data = $this->assertStatus(200, $this->adminRequest(
            'PUT',
            "/admin/roles/" . self::ADMIN_ROLE,
            ['description' => 'Full admin access']
        ));

        self::assertSame('Full admin access', $data['description']);
        self::assertSame('admin', $data['name']);
    }

    public function testUpdateRoleName(): void
    {
        $roleId = getGuid();
        self::$pdo->prepare(
            "INSERT INTO roles (id, realm_id, name) VALUES (?, ?, ?)"
        )->execute([$roleId, self::TEST_REALM, 'temp-role']);

        $data = $this->assertStatus(200, $this->adminRequest(
            'PUT',
            "/admin/roles/$roleId",
            ['name' => 'renamed-role']
        ));

        self::assertSame('renamed-role', $data['name']);
    }

    public function testDeleteRole(): void
    {
        $roleId = getGuid();
        self::$pdo->prepare(
            "INSERT INTO roles (id, realm_id, name) VALUES (?, ?, ?)"
        )->execute([$roleId, self::TEST_REALM, 'deletable-role']);

        $this->assertStatus(204, $this->adminRequest(
            'DELETE',
            "/admin/roles/$roleId"
        ));

        $this->assertStatus(404, $this->adminRequest(
            'GET',
            "/admin/roles/$roleId"
        ));
    }

    public function testDeleteRoleAssignedToUserReturns409(): void
    {
        $this->assertStatus(409, $this->adminRequest(
            'DELETE',
            "/admin/roles/" . self::BASIC_ROLE
        ));
    }

    // ── User Role Assignments ───────────────────────────────

    public function testListUserRoles(): void
    {
        $data = $this->assertStatus(200, $this->adminRequest(
            'GET',
            "/admin/users/" . self::TEST_USER . "/roles"
        ));

        self::assertArrayHasKey('items', $data);
        self::assertGreaterThan(0, $data['total']);
        self::assertLessThanOrEqual($data['limit'], count($data['items']));
        $roleNames = array_column($data['items'], 'name');
        self::assertContains('basic', $roleNames);
    }

    public function testAssignRoleToUser(): void
    {
        $newRoleId = getGuid();
        self::$pdo->prepare(
            "INSERT INTO roles (id, realm_id, name) VALUES (?, ?, ?)"
        )->execute([$newRoleId, self::TEST_REALM, 'assignable-role']);

        $data = $this->assertStatus(201, $this->adminRequest(
            'POST',
            "/admin/users/" . self::TEST_USER . "/roles",
            ['role_id' => $newRoleId]
        ));

        self::assertSame($newRoleId, $data['id']);
        self::assertSame('assignable-role', $data['name']);
    }

    public function testAssignRoleToUserNotFoundReturns400(): void
    {
        $this->assertStatus(400, $this->adminRequest(
            'POST',
            "/admin/users/" . self::TEST_USER . "/roles",
            ['role_id' => getGuid()]
        ));
    }

    public function testAssignRoleFromAnotherRealmReturns400(): void
    {
        $otherRealmId = (string) self::$pdo
            ->query("SELECT id FROM realms WHERE id <> '" . self::TEST_REALM . "' LIMIT 1")
            ->fetchColumn();
        $foreignRealmRoleId = getGuid();
        $this->insertRole($foreignRealmRoleId, $otherRealmId, 'foreign-realm-role');

        $this->assertStatus(400, $this->assignRoleRequest(
            self::TEST_USER,
            $foreignRealmRoleId
        ));

        $roles = self::$app->getContainer()->get(\AuthServer\Interfaces\RoleRepository::class);
        self::assertFalse($roles->userHasRole(self::TEST_USER, $foreignRealmRoleId));
    }

    public function testAssignRoleToUnknownUserReturns404(): void
    {
        $this->assertStatus(404, $this->adminRequest(
            'POST',
            "/admin/users/" . getGuid() . "/roles",
            ['role_id' => self::BASIC_ROLE]
        ));
    }

    public function testRemoveRoleFromUser(): void
    {
        $newRoleId = getGuid();
        self::$pdo->prepare(
            "INSERT INTO roles (id, realm_id, name) VALUES (?, ?, ?)"
        )->execute([$newRoleId, self::TEST_REALM, 'removable-role']);

        self::$pdo->prepare(
            "INSERT OR IGNORE INTO user_role_assignments (user_id, role_id) VALUES (?, ?)"
        )->execute([self::TEST_USER, $newRoleId]);

        $this->assertStatus(204, $this->adminRequest(
            'DELETE',
            "/admin/users/" . self::TEST_USER . "/roles/$newRoleId"
        ));
    }

    public function testRemoveNonAssignedRoleIsIdempotent(): void
    {
        $unassignedRoleId = getGuid();
        self::$pdo->prepare(
            "INSERT INTO roles (id, realm_id, name) VALUES (?, ?, ?)"
        )->execute([$unassignedRoleId, self::TEST_REALM, 'unassigned-role']);

        $this->assertStatus(204, $this->adminRequest(
            'DELETE',
            "/admin/users/" . self::TEST_USER . "/roles/$unassignedRoleId"
        ));
    }

    public function testRemoveNonExistentRoleIdIsIdempotent(): void
    {
        $this->assertStatus(204, $this->adminRequest(
            'DELETE',
            "/admin/users/" . self::TEST_USER . "/roles/" . getGuid()
        ));
    }

    // ── Scope-Role Mappings ─────────────────────────────────

    public function testFindScopeRoleMappingReturnsValueObject(): void
    {
        $roles = self::$app->getContainer()->get(\AuthServer\Interfaces\RoleRepository::class);

        self::$pdo->prepare(
            'INSERT OR IGNORE INTO client_scope_roles (client_id, scope, role_id, required)
             VALUES (:client_id, :scope, :role_id, :required)'
        )->execute([
            ':client_id' => self::KC_APP_CLIENT,
            ':scope' => 'email',
            ':role_id' => self::ADMIN_ROLE,
            ':required' => 1,
        ]);

        $mapping = $roles->findScopeRoleMapping(self::KC_APP_CLIENT, 'email', self::ADMIN_ROLE);

        self::assertInstanceOf(\AuthServer\Models\ScopeRoleMapping::class, $mapping);
        self::assertSame(self::ADMIN_ROLE, $mapping->roleId);
        self::assertSame('email', $mapping->scope);
        self::assertSame('admin', $mapping->roleName);
        self::assertTrue($mapping->required);
    }

    public function testFindScopeRoleMappingReturnsNullWhenNotFound(): void
    {
        $roles = self::$app->getContainer()->get(\AuthServer\Interfaces\RoleRepository::class);

        $mapping = $roles->findScopeRoleMapping(self::KC_APP_CLIENT, 'nonexistent', getGuid());

        self::assertNull($mapping);
    }

    public function testListScopeRolesEmpty(): void
    {
        $data = $this->assertStatus(200, $this->adminRequest(
            'GET',
            "/admin/clients/" . self::KC_APP_CLIENT . "/scope-roles"
        ));

        self::assertArrayHasKey('items', $data);
        self::assertSame($data['total'], count($data['items']));
        self::assertGreaterThanOrEqual(0, $data['total']);
    }

    public function testCreateScopeRoleMapping(): void
    {
        $data = $this->assertStatus(201, $this->adminRequest(
            'POST',
            "/admin/clients/" . self::KC_APP_CLIENT . "/scope-roles",
            [
                'scope' => 'profile',
                'role_id' => self::ADMIN_ROLE,
                'required' => true,
            ]
        ));

        self::assertSame('profile', $data['scope']);
        self::assertSame(self::ADMIN_ROLE, $data['role_id']);
        self::assertTrue($data['required']);
    }

    public function testCreateScopeRoleMappingDuplicateReturns409(): void
    {
        $this->assertStatus(409, $this->adminRequest(
            'POST',
            "/admin/clients/" . self::KC_APP_CLIENT . "/scope-roles",
            [
                'scope' => 'profile',
                'role_id' => self::ADMIN_ROLE,
            ]
        ));
    }

    public function testCreateScopeRoleMappingUnknownRoleReturns400(): void
    {
        $this->assertStatus(400, $this->adminRequest(
            'POST',
            "/admin/clients/" . self::KC_APP_CLIENT . "/scope-roles",
            [
                'scope' => 'admin',
                'role_id' => getGuid(),
            ]
        ));
    }

    public function testCreateScopeRoleMappingUnknownClientReturns404(): void
    {
        $this->assertStatus(404, $this->adminRequest(
            'POST',
            "/admin/clients/" . getGuid() . "/scope-roles",
            [
                'scope' => 'admin',
                'role_id' => self::ADMIN_ROLE,
            ]
        ));
    }

    public function testCreateScopeRoleMappingWithInvalidScopeReturns400(): void
    {
        $this->assertStatus(400, $this->adminRequest(
            'POST',
            "/admin/clients/" . self::KC_APP_CLIENT . "/scope-roles",
            [
                'scope' => 'nonexistent-scope',
                'role_id' => self::ADMIN_ROLE,
            ]
        ));
    }

    public function testListScopeRolesAfterCreate(): void
    {
        $data = $this->assertStatus(200, $this->adminRequest(
            'GET',
            "/admin/clients/" . self::KC_APP_CLIENT . "/scope-roles"
        ));

        self::assertGreaterThan(0, $data['total']);
        $found = false;
        foreach ($data['items'] as $mapping) {
            if ($mapping['scope'] === 'profile' && $mapping['role_id'] === self::ADMIN_ROLE) {
                $found = true;
                self::assertTrue($mapping['required']);
            }
        }
        self::assertTrue($found, 'Expected scope-role mapping not found');
    }

    public function testUpdateScopeRoleMapping(): void
    {
        $data = $this->assertStatus(200, $this->adminRequest(
            'PUT',
            "/admin/clients/" . self::KC_APP_CLIENT . "/scope-roles/profile/" . self::ADMIN_ROLE,
            ['required' => false]
        ));

        self::assertSame('profile', $data['scope']);
        self::assertSame(self::ADMIN_ROLE, $data['role_id']);
        self::assertFalse($data['required']);
    }

    public function testUpdateScopeRoleMappingNotFound(): void
    {
        $this->assertStatus(404, $this->adminRequest(
            'PUT',
            "/admin/clients/" . self::KC_APP_CLIENT . "/scope-roles/openid/" . self::ADMIN_ROLE,
            ['required' => true]
        ));
    }

    public function testDeleteScopeRoleMapping(): void
    {
        $this->assertStatus(204, $this->adminRequest(
            'DELETE',
            "/admin/clients/" . self::KC_APP_CLIENT . "/scope-roles/profile/" . self::ADMIN_ROLE
        ));

        $data = $this->assertStatus(200, $this->adminRequest(
            'GET',
            "/admin/clients/" . self::KC_APP_CLIENT . "/scope-roles"
        ));

        foreach ($data['items'] as $mapping) {
            self::assertFalse(
                $mapping['scope'] === 'profile' && $mapping['role_id'] === self::ADMIN_ROLE,
                'Mapping should have been deleted'
            );
        }
    }

    public function testDeleteScopeRoleMappingNonexistentIsIdempotent(): void
    {
        $this->assertStatus(204, $this->adminRequest(
            'DELETE',
            "/admin/clients/" . self::KC_APP_CLIENT . "/scope-roles/nonexistent/" . self::ADMIN_ROLE
        ));
    }

    public function testDeleteRoleWithScopeRoleMappingReturns409(): void
    {
        $roleId = getGuid();
        self::$pdo->prepare(
            "INSERT INTO roles (id, realm_id, name) VALUES (?, ?, ?)"
        )->execute([$roleId, self::TEST_REALM, 'scoped-role']);

        self::$pdo->prepare(
            "INSERT INTO client_scope_roles (client_id, scope, role_id, required) VALUES (?, ?, ?, 0)"
        )->execute([self::KC_APP_CLIENT, 'email', $roleId]);

        $this->assertStatus(409, $this->adminRequest(
            'DELETE',
            "/admin/roles/$roleId"
        ));
    }

    private function insertRole(string $roleId, string $realmId, string $name): void
    {
        self::$pdo->prepare(
            "INSERT INTO roles (id, realm_id, name) VALUES (?, ?, ?)"
        )->execute([$roleId, $realmId, $name]);
    }

    private function assignRoleRequest(string $userId, string $roleId): mixed
    {
        return $this->adminRequest('POST', "/admin/users/{$userId}/roles", ['role_id' => $roleId]);
    }
}

