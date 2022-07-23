<?php

namespace AuthServer\Interfaces;

use AuthServer\Models\Realm;


interface RealmRepository
{
  public function find_by_id(string $id): ?Realm;
  public function find_by_name(string $id): ?Realm;
}
