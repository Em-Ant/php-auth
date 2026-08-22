<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Repositories\MigrationRepository;
use AuthServer\Repositories\RoleRepository;
use AuthServer\Services\Database;
use AuthServer\Services\MigrationRunner;
use AuthServer\Tests\Support\RealmFixture;
use PHPUnit\Framework\TestCase;

/**
 * Verifies the 005_roles data migration: legacy users.realm_roles is moved
 * into normalized realm roles + assignments (client_id IS NULL). Client roles
 * are a separate namespace and are never derived from realm roles.
 */
class RolesMigrationTest extends TestCase
{
    private const REALM = '11111111-1111-4111-8111-111111111111';
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

    /**
     * The migration abandons users.realm_roles but must not drop it: DROP
     * COLUMN needs SQLite >= 3.35, which some shared hosts do not ship.
     */
    public function testLegacyColumnIsRetainedNotDropped(): void
    {
        $columns = self::$pdo->query("PRAGMA table_info(users)")->fetchAll();
        $names = array_map(fn(array $c) => $c['name'], $columns);

        self::assertContains('realm_roles', $names);
    }
}
