<?php

declare(strict_types=1);

namespace AuthServer\Interfaces;

use AuthServer\Models\OfflineSession;

interface OfflineSessionRepository
{
    public function findById(string $id): ?OfflineSession;
    public function findByRefreshToken(string $token, string $realmId): ?OfflineSession;

    public function create(OfflineSession $offlineSession): OfflineSession;

    public function refresh(
        string $id,
        string $token
    ): bool;

    public function setExpired(
        string $id
    ): bool;

    public function countActiveByUserId(string $userId): int;

    public function countActiveByClientId(string $clientId): int;

    public function setExpiredByUserId(string $userId): int;

    public function setExpiredByClientId(string $clientId): int;

    /**
     * Filtered, paged listing. `total` counts all rows matching the filters,
     * independent of limit/offset.
     *
     * @return array{items: \AuthServer\Models\OfflineSession[], total: int}
     */
    public function searchAll(
        ?string $realmId,
        ?string $userId,
        ?string $clientId,
        int $limit,
        int $offset
    ): array;

    public function deleteByUserId(string $userId): int;

    public function deleteByClientId(string $clientId): int;
}
