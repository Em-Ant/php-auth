<?php

declare(strict_types=1);

namespace AuthServer\Interfaces;

use AuthServer\Models\Session;

interface SessionRepository
{
    public function findById(string $id): ?Session;

    public function create(
        string $realm_id,
        string $user_id,
        string $acr
    ): ?Session;

    public function refresh(
        string $id
    ): bool;

    public function setExpired(
        string $id
    ): bool;

    public function delete(string $id): bool;

    public function findAll(?string $realmId = null, ?string $userId = null): array;

    /**
     * Filtered, paged listing; `total` covers all rows matching the filters.
     *
     * @return array{items: Session[], total: int}
     */
    public function searchAll(?string $realmId, ?string $userId, int $limit, int $offset): array;

    public function countByUserId(string $userId): int;

    public function countActiveByUserId(string $userId): int;

    public function deleteExpired(): int;
}
