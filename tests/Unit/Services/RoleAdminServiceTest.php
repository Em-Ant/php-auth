<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Services;

use AuthServer\Exceptions\ConflictException;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\ClientRepository;
use AuthServer\Interfaces\RealmRepository;
use AuthServer\Interfaces\RoleRepository;
use AuthServer\Models\Realm;
use AuthServer\Models\Role;
use AuthServer\Services\AuditLogWriter;
use AuthServer\Services\RoleAdminService;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\NullLogger;
use Slim\Psr7\Factory\ServerRequestFactory;

class RoleAdminServiceTest extends TestCase
{
    public function testDeleteRoleAssignedToUsersThrowsConflict(): void
    {
        $this->expectException(ConflictException::class);
        $this->serviceWith(1, 0)->deleteRole('role-1', $this->adminRequest());
    }

    public function testDeleteRoleWithScopeRoleMappingsThrowsConflict(): void
    {
        $this->expectException(ConflictException::class);
        $this->serviceWith(0, 1)->deleteRole('role-1', $this->adminRequest());
    }

    public function testDeleteRoleSucceedsWhenNoAssignments(): void
    {
        $roles = $this->rolesMockReturning(0, 0);
        $roles->expects(self::once())->method('delete')->with('role-1')->willReturn(true);

        $svc = $this->service($roles);

        $result = $svc->deleteRole('role-1', $this->adminRequest());

        self::assertTrue($result);
    }

    public function testCreateRoleValidatesRealmAndClientReferences(): void
    {
        $roles = $this->createMock(RoleRepository::class);
        $roles->method('findAll')->willReturn([]);

        $realms = $this->createMock(RealmRepository::class);
        $realms->method('findById')->willReturn(null);

        $svc = $this->service($roles, $realms);

        $this->expectException(ValidationFailed::class);
        $svc->create('realm-unknown', null, ['name' => 'admin'], $this->adminRequest());
    }

    public function testCreateRoleRejectsDuplicateInSameContext(): void
    {
        $existing = $this->role('admin');
        $roles = $this->rolesRepoWith($existing);

        $svc = $this->service($roles, $this->realmsRepo());

        $this->expectException(ConflictException::class);
        $svc->create('realm-1', null, ['name' => 'admin'], $this->adminRequest());
    }

    public function testCreateRolePersistsNewRole(): void
    {
        $roles = $this->createMock(RoleRepository::class);
        $roles->method('findAll')->willReturn([]);
        $roles->expects(self::once())->method('create')->willReturnCallback(
            fn(Role $role) => $role
        );

        $clients = $this->createMock(ClientRepository::class);
        $clients->method('findById')->willReturn(null);

        $svc = $this->service($roles, $this->realmsRepo(), $clients);

        $created = $svc->create('realm-1', null, ['name' => 'admin', 'description' => 'Admins'], $this->adminRequest());

        self::assertSame('admin', $created->getName());
        self::assertSame('Admins', $created->getDescription());
    }

    public function testUpdateRolePersistsChanges(): void
    {
        $existing = $this->role('admin');
        $roles = $this->rolesRepoWith($existing);
        $roles->expects(self::once())->method('update')->willReturn(true);

        $svc = $this->service($roles);

        $updated = $svc->update($existing, ['name' => 'super-admin', 'description' => 'Top'], $this->adminRequest());

        self::assertSame('super-admin', $updated->getName());
        self::assertSame('Top', $updated->getDescription());
    }

    public function testGuardsAndDeleteRunInsideOneTransaction(): void
    {
        $pdo = new \PDO('sqlite::memory:');
        $transactionsDuringGuard = null;
        $transactionsDuringDelete = null;

        $roles = $this->createMock(RoleRepository::class);
        $roles->method('countUsersByRoleId')->willReturnCallback(
            function () use ($pdo, &$transactionsDuringGuard): int {
                $transactionsDuringGuard = $pdo->inTransaction();
                return 0;
            }
        );
        $roles->method('countScopeRoleMappingsByRoleId')->willReturn(0);
        $roles->method('delete')->willReturnCallback(
            function () use ($pdo, &$transactionsDuringDelete): bool {
                $transactionsDuringDelete = $pdo->inTransaction();
                return true;
            }
        );

        $svc = $this->service($roles, null, null, $pdo);
        $svc->deleteRole('role-1', $this->adminRequest());

        self::assertTrue($transactionsDuringGuard, 'guards must run inside the transaction');
        self::assertTrue($transactionsDuringDelete, 'delete must run inside the same transaction');
        self::assertFalse($pdo->inTransaction(), 'transaction must be committed afterwards');
    }

    public function testConflictLeavesNoOpenTransactionBehind(): void
    {
        $pdo = new \PDO('sqlite::memory:');
        $roles = $this->createMock(RoleRepository::class);
        $roles->method('countUsersByRoleId')->willReturn(1);

        $svc = $this->service($roles, null, null, $pdo);

        try {
            $svc->deleteRole('role-1', $this->adminRequest());
            self::fail('expected ConflictException');
        } catch (ConflictException) {
            // expected
        }

        self::assertFalse($pdo->inTransaction());
    }

    public function testParticipatesInCallerOwnedTransactionWithoutCommittingIt(): void
    {
        $pdo = new \PDO('sqlite::memory:');
        $pdo->beginTransaction();

        $roles = $this->createMock(RoleRepository::class);
        $roles->method('countUsersByRoleId')->willReturn(0);
        $roles->method('countScopeRoleMappingsByRoleId')->willReturn(0);
        $roles->method('delete')->willReturn(true);

        $svc = $this->service($roles, null, null, $pdo);
        $svc->deleteRole('role-1', $this->adminRequest());

        self::assertTrue($pdo->inTransaction(), 'caller-owned transaction must not be committed or rolled back');

        $pdo->rollBack();
    }

    private function serviceWith(int $userAssignments, int $mappingReferences): RoleAdminService
    {
        return $this->service($this->rolesMockReturning($userAssignments, $mappingReferences));
    }

    private function rolesMockReturning(int $userAssignments, int $mappingReferences): RoleRepository
    {
        $roles = $this->createMock(RoleRepository::class);
        $roles->method('countUsersByRoleId')->willReturn($userAssignments);
        $roles->method('countScopeRoleMappingsByRoleId')->willReturn($mappingReferences);

        return $roles;
    }

    private function service(
        RoleRepository $roles,
        ?RealmRepository $realms = null,
        ?ClientRepository $clients = null,
        ?\PDO $pdo = null
    ): RoleAdminService {
        return new RoleAdminService(
            $pdo ?? new \PDO('sqlite::memory:'),
            $roles,
            $realms ?? $this->createMock(RealmRepository::class),
            $clients ?? $this->createMock(ClientRepository::class),
            new AuditLogWriter(
                $this->createMock(\AuthServer\Interfaces\AuditLogRepository::class),
                new NullLogger(),
            ),
        );
    }

    private function role(string $name): Role
    {
        return new Role('role-1', 'realm-1', null, $name, null, new \DateTime('2026-01-01', new \DateTimeZone('UTC')));
    }

    private function rolesRepoWith(Role $existing): RoleRepository
    {
        $roles = $this->createMock(RoleRepository::class);
        $roles->method('findAll')->willReturn([$existing]);
        return $roles;
    }

    private function realmsRepo(): RealmRepository
    {
        $realms = $this->createMock(RealmRepository::class);
        $realms->method('findById')->willReturnCallback(
            fn(string $id) => $id === 'realm-1' ? $this->realm() : null
        );
        return $realms;
    }

    private function realm(): Realm
    {
        return new Realm(
            'realm-1',
            'test',
            'keys-1',
            1800,
            300,
            1800,
            1800,
            86400,
            1800,
            'openid profile email',
            '2026-01-01 00:00:00'
        );
    }

    private function adminRequest(): ServerRequestInterface
    {
        return (new ServerRequestFactory())->createServerRequest('GET', '/')
            ->withAttribute('admin_claims', ['sub' => 'admin-user'])
            ->withAttribute('admin_user', 'admin-user');
    }
}
