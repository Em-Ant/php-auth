<?php

declare(strict_types=1);

namespace AuthServer\Interfaces;

use AuthServer\Models\AuditLogEntry;

interface AuditLogRepository
{
    public function findById(string $id): ?AuditLogEntry;

    public function create(AuditLogEntry $entry): AuditLogEntry;

    /**
     * @return array{items: AuditLogEntry[], total: int}
     */
    public function searchAll(
        ?string $action,
        ?string $actorType,
        ?string $targetType,
        ?string $realmId,
        ?string $from,
        ?string $to,
        int $limit,
        int $offset,
    ): array;

    public function purge(?string $realmId, ?string $olderThan): int;
}
