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
        $roles = $this->createMock(RoleRepository::class);
        $roles->method('countUsersByRoleId')->willReturn(1);
        $roles->method('countScopeRoleMappingsByRoleId')->willReturn(0);

        $svc = new RoleAdminService($roles);

        $this->expectException(ConflictException::class);
        $svc->deleteRole('role-1');
    }

    public function testDeleteRoleWithScopeRoleMappingsThrowsConflict(): void
    {
        $roles = $this->createMock(RoleRepository::class);
        $roles->method('countUsersByRoleId')->willReturn(0);
        $roles->method('countScopeRoleMappingsByRoleId')->willReturn(1);

        $svc = new RoleAdminService($roles);

        $this->expectException(ConflictException::class);
        $svc->deleteRole('role-1');
    }

    public function testDeleteRoleSucceedsWhenNoAssignments(): void
    {
        $roles = $this->createMock(RoleRepository::class);
        $roles->method('countUsersByRoleId')->willReturn(0);
        $roles->method('countScopeRoleMappingsByRoleId')->willReturn(0);
        $roles->expects(self::once())->method('delete')->with('role-1')->willReturn(true);

        $svc = new RoleAdminService($roles);

        $result = $svc->deleteRole('role-1');

        self::assertTrue($result);
    }
}
