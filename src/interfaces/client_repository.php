<?php

namespace AuthServer\Interfaces;

use AuthServer\Models\Client;

require_once 'src/models/client.php';

interface ClientRepository
{
  public function find_by_id(string $id): ?Client;
  public function find_by_client_id(string $id): ?Client;
}
