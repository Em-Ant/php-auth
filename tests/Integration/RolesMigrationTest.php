<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Repositories\MigrationRepository;
use AuthServer\Repositories\RoleRepository;
use AuthServer\Models\Role;
use AuthServer\Services\Database;
use AuthServer\Services\MigrationRunner;
use AuthServer\Tests\Support\RealmFixture;
use PHPUnit\Framework\TestCase;

/**
 * Verifies the 005_roles data migration: legacy users.realm_roles is moved
 * into normalized realm roles + assignments, and every realm role is mirrored
 * as a client role on each client of the realm (the pre-migration behaviour
 * where clients inherited the whole realm-role namespace).
 */
class RolesMigrationTest extends TestCase
{
    private const REALM = '11111111-1111-4111-8111-111111111111';
    private const CLIENT_A = '22222222-2222-4222-8222-222222222221';
    private const CLIENT_B = '22222222-2222-4222-8222-222222222222';
    private const USER_ADMIN = '33333333-3333-4333-8333-333333333331';
    private const USER_BASIC = '33333333-3333-4333-8333-333333333332';

    private static \PDO $pdo;
    private RoleRepository $roles;

    public static function setUpBeforeClass(): void
    {
        self::$pdo = Database::connect('sqlite::memory:');
        self::$pdo->exec('PRAGMA foreign_keys = ON');

        $runner = new MigrationRunner(
            new MigrationRepository(self::$pdo),
            __DIR__ . '/../../migrations/'
        );
        $runner->go(4);

        self::seedLegacySchema();

        $runner->go(5);
    }

    public function setUp(): void
    {
        $this->roles = new RoleRepository(self::$pdo);
    }

    private static function seedLegacySchema(): void
    {
        RealmFixture::createRealm(self::$pdo, self::REALM, 'legacy');

        foreach ([self::CLIENT_A => 'app_a', self::CLIENT_B => 'app_b'] as $id => $name) {
            RealmFixture::createClient(self::$pdo, $id, $name, self::REALM);
        }

        foreach ([
            self::USER_ADMIN => 'basic admin',
            self::USER_BASIC => 'basic',
        ] as $id => $roles) {
            self::$pdo->exec(
                "INSERT INTO users (id, realm_id, email, password, realm_roles)
                 VALUES ('$id', '" . self::REALM . "', '$id@example.com', 'x', '$roles')"
            );
        }
    }

    public function testRealmRolesColumnIsDropped(): void
    {
        $columns = self::$pdo->query("PRAGMA table_info(users)")->fetchAll();
        $names = array_map(fn(array $c) => $c['name'], $columns);

        self::assertNotContains('realm_roles', $names);
    }

    public function testLegacyRolesAreNormalizedAsRealmRoles(): void
    {
        foreach ([
            self::USER_ADMIN => ['admin', 'basic'],
            self::USER_BASIC => ['basic'],
        ] as $userId => $expected) {
            self::assertSame(
                $expected,
                $this->roles->findRealmRoleNamesByUserId($userId, self::REALM)
            );
        }
    }

    public function testRealmRolesAreMirroredOnEveryClientOfTheRealm(): void
    {
        foreach ([self::CLIENT_A, self::CLIENT_B] as $clientId) {
            $names = array_map(
                fn(Role $r) => $r->getName(),
                $this->roles->findAll(self::REALM, $clientId)
            );
            self::assertSame(['admin', 'basic'], $names);
        }
    }

    public function testClientRoleAssignmentsMirrorTheUserRealmRoles(): void
    {
        self::assertSame(
            ['app_a' => ['admin', 'basic'], 'app_b' => ['admin', 'basic']],
            $this->roles->findClientRoleNamesByUserId(self::USER_ADMIN, self::REALM)
        );
        self::assertSame(
            ['app_a' => ['basic'], 'app_b' => ['basic']],
            $this->roles->findClientRoleNamesByUserId(self::USER_BASIC, self::REALM)
        );
    }
}
