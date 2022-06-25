<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Interfaces\ClientRepository as IRepo;
use AuthServer\Models\Client;
use AuthServer\Repositories\DataSource;
use Error;

require_once 'src/interfaces/client_repository.php';

class ClientRepository implements IRepo
{
  private \PDO $db;

  public function __construct(Datasource $datasource)
  {
    $this->db = $datasource->getDb();
  }

  public function findById(string $id): ?Client
  {
    try {
      $statement = $this->db->prepare(
        "SELECT * FROM clients WHERE id = :id"
      );
      $statement->bindValue(':id', $id);

      $statement->execute();

      $r = $statement->fetch();

      return new Client((string) $r['id'], $r['client_id'], $r['uri'], $r['client_secret']);
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return null;
    }
  }

  public function findByClientId(string $client_id): ?Client
  {
    try {

      $statement = $this->db->prepare(
        "SELECT * FROM clients WHERE client_id = :id"
      );
      $statement->bindValue(':id', $client_id);

      $statement->execute();

      $r = $statement->fetch();

      return new Client((string) $r['id'], $r['client_id'], $r['uri'], $r['client_secret']);
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return null;
    }
  }
}
