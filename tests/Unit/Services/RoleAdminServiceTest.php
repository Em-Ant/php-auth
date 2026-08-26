<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Services;

use AuthServer\Exceptions\ConflictException;
use AuthServer\Interfaces\RoleRepository;
use AuthServer\Services\RoleAdminService;
use PHPUnit\Framework\TestCase;

class RoleAdminServiceTest extends TestCase
{
    public function testDeleteRoleAssignedToUsersThrowsConflict(): void
    {
        $this->expectException(ConflictException::class);
        $this->serviceWith(1, 0)->deleteRole('role-1');
    }

    public function testDeleteRoleWithScopeRoleMappingsThrowsConflict(): void
    {
        $this->expectException(ConflictException::class);
        $this->serviceWith(0, 1)->deleteRole('role-1');
    }

    public function testDeleteRoleSucceedsWhenNoAssignments(): void
    {
        $roles = $this->rolesMockReturning(0, 0);
        $roles->expects(self::once())->method('delete')->with('role-1')->willReturn(true);

        $svc = new RoleAdminService(new \PDO('sqlite::memory:'), $roles);

        $result = $svc->deleteRole('role-1');

        self::assertTrue($result);
    }

    private function serviceWith(int $userAssignments, int $mappingReferences): RoleAdminService
    {
        return new RoleAdminService(new \PDO('sqlite::memory:'), $this->rolesMockReturning($userAssignments, $mappingReferences));
    }

    private function rolesMockReturning(int $userAssignments, int $mappingReferences): RoleRepository
    {
        $roles = $this->createMock(RoleRepository::class);
        $roles->method('countUsersByRoleId')->willReturn($userAssignments);
        $roles->method('countScopeRoleMappingsByRoleId')->willReturn($mappingReferences);

        return $roles;
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

        $svc = new RoleAdminService($pdo, $roles);
        $svc->deleteRole('role-1');

        self::assertTrue($transactionsDuringGuard, 'guards must run inside the transaction');
        self::assertTrue($transactionsDuringDelete, 'delete must run inside the same transaction');
        self::assertFalse($pdo->inTransaction(), 'transaction must be committed afterwards');
    }

    public function testConflictLeavesNoOpenTransactionBehind(): void
    {
        $pdo = new \PDO('sqlite::memory:');
        $roles = $this->createMock(RoleRepository::class);
        $roles->method('countUsersByRoleId')->willReturn(1);

        $svc = new RoleAdminService($pdo, $roles);

        try {
            $svc->deleteRole('role-1');
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

        $svc = new RoleAdminService($pdo, $roles);
        $svc->deleteRole('role-1');

        self::assertTrue($pdo->inTransaction(), 'caller-owned transaction must not be committed or rolled back');

        $pdo->rollBack();
    }
}

