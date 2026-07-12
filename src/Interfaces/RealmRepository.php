<?php

namespace AuthServer\Interfaces;

use AuthServer\Models\Realm;

interface RealmRepository
{
    public function findById(string $id): ?Realm;
    public function findByName(string $id): ?Realm;
}
