<?php

declare(strict_types=1);

namespace AuthServer\Interfaces;

use AuthServer\Models\Realm;

interface RealmRepository
{
    public function findById(string $id): ?Realm;
    public function findByName(string $id): ?Realm;

    /** @return Realm[] */
    public function findAll(): array;

    public function create(Realm $realm): Realm;

    public function update(Realm $realm): bool;

    public function delete(string $id): bool;
}
