<?php

declare(strict_types=1);

namespace AuthServer\Interfaces;

use AuthServer\Models\Client;

interface ClientRepository
{
    public function findById(string $id): ?Client;

    public function findByName(string $id): ?Client;

    /**
     * Filtered, paged listing; `total` covers all rows matching the filters.
     *
     * @return array{items: Client[], total: int}
     */
    public function searchAll(?string $realmId, int $limit, int $offset): array;

    public function create(Client $client): Client;

    public function update(Client $client): bool;

    public function delete(string $id): bool;

    public function countByRealmId(string $realmId): int;
}
