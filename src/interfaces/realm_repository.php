<?php

namespace AuthServer\Interfaces;

use AuthServer\Models\Realm;

require_once 'src/models/realm.php';

interface RealmRepository
{
  public function find_by_id(string $id): ?Realm;
  public function find_by_name(string $id): ?Realm;
}
