<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Interfaces\ClientRepository as IRepo;
use AuthServer\Models\Client;
use AuthServer\Repositories\DataSource;

require_once 'src/interfaces/client_repository.php';
require_once 'src/models/client.php';


class ClientRepository implements IRepo
{
  private \PDO $db;

  public function __construct(Datasource $datasource)
  {
    $this->db = $datasource->getDb();
  }

  public function find_by_id(string $id): ?Client
  {
    try {
      $statement = $this->db->prepare(
        "SELECT * FROM clients WHERE id = :id"
      );
      $statement->bindValue(':id', $id);

      $statement->execute();

      $r = $statement->fetch();

      if (!$r) return null;

      return new Client(
        $r['id'],
        $r['client_id'],
        $r['client_secret'],
        $r['scopes'],
        $r['uri'],
        $r['created_at']
      );
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return null;
    }
  }

  public function find_by_client_id(string $client_id): ?Client
  {
    try {

      $statement = $this->db->prepare(
        "SELECT * FROM clients WHERE client_id = :id"
      );
      $statement->bindValue(':id', $client_id);

      $statement->execute();

      $r = $statement->fetch();

      if (!$r) return null;

      return new Client(
        $r['id'],
        $r['client_id'],
        $r['client_secret'],
        $r['scopes'],
        $r['uri'],
        $r['created_at']
      );
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return null;
    }
  }
}
