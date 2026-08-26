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
     *
     * @return array{items: User[], total: int}
     */
    public function searchAll(?string $realmId, int $limit, int $offset): array;

    public function create(User $user): User;

    public function update(User $user): bool;

    public function delete(string $id): bool;

    public function countByRealmId(string $realmId): int;
}
