<?php

declare(strict_types=1);

namespace AuthServer\Models;

/**
 * The outcome of issuance-time scope/role resolution: the narrowed scope
 * string carried by every token of the bundle, plus the role claims.
 */
final class IssuedGrant
{
    public function __construct(
        public readonly string $scope,
        public readonly RoleClaims $roleClaims,
    ) {
    }
}
