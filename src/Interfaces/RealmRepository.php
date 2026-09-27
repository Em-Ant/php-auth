<?php

declare(strict_types=1);

namespace AuthServer\Interfaces;

use AuthServer\Models\Realm;

interface RealmRepository
{
    public function findById(string $id): ?Realm;
    public function findByName(string $id): ?Realm;

    /**
     * Paged listing; `total` covers all rows.
     *
     * @return array{items: Realm[], total: int}
     */
    public function searchAll(int $limit, int $offset): array;

    public function create(Realm $realm): Realm;

    public function update(Realm $realm): bool;

    public function delete(string $id): bool;
}
