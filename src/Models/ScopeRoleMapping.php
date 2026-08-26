<?php

declare(strict_types=1);

namespace AuthServer\Models;

/**
 * One role scope mapping of a client: when `scope` is granted, the mapped
 * role is included in the token (if the user holds it); a `required` mapping
 * drops the whole scope at issuance when the user lacks the role.
 */
final class ScopeRoleMapping
{
    public function __construct(
        public readonly string $roleId,
        public readonly string $scope,
        public readonly string $roleName,
        public readonly ?string $roleClientName,
        public readonly bool $required,
    ) {
    }

    public function isRealmRole(): bool
    {
        return $this->roleClientName === null;
    }
}
