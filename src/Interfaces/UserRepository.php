<?php

declare(strict_types=1);

namespace AuthServer\Interfaces;

use AuthServer\Models\User;

interface UserRepository
{
    public function findById(string $id): ?User;

    public function findByEmailAndRealmId(string $email, string $realm_id): ?User;

    /**
     * Filtered, paged listing; `total` covers all rows matching the filters.
     * `$q` is a bound LIKE pattern (see ValidatesAdminInput::searchTerm).
     *
     * @return array{items: User[], total: int}
     */
    public function searchAll(?string $realmId, int $limit, int $offset, ?string $q = null): array;

    public function create(User $user): User;

    public function update(User $user): bool;

    public function delete(string $id): bool;

    public function countByRealmId(string $realmId): int;
}
