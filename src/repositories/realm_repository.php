<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Interfaces\RealmRepository as IRepo;
use AuthServer\Models\Realm;
use AuthServer\Repositories\DataSource;
use Error;

require_once 'src/interfaces/realm_repository.php';
require_once 'src/models/realm.php';


class RealmRepository implements IRepo
{
  private \PDO $db;

  public function __construct(DataSource $data_source)
  {
    $this->db = $data_source->getDb();
  }

  public function find_by_id(string $id): ?Realm
  {
    try {
      $statement = $this->db->prepare(
        "SELECT * FROM realms WHERE id = :id"
      );
      $statement->bindValue(':id', $id);

      $statement->execute();

      $r = $statement->fetch();

      if (!$r) {
        return null;
      }

      return new Realm(
        $r['id'],
        $r['name'],
        $r['keys_id'],
        (int) $r['refresh_token_expires_in'],
        (int) $r['access_token_expires_in'],
        (int) $r['pending_login_expires_in'],
        (int) $r['authenticated_login_expires_in'],
        (int) $r['session_expires_in'],
        (int) $r['idle_session_expires_in'],
        $r['scopes'],
        $r['created_at']
      );
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return null;
    }
  }

  public function find_by_name(string $name): ?Realm
  {
    try {

      $statement = $this->db->prepare(
        "SELECT * FROM realms WHERE name = :name"
      );
      $statement->bindValue(':name', $name);

      $statement->execute();

      $r = $statement->fetch();

      if (!$r) {
        return null;
      }

      return new Realm(
        $r['id'],
        $r['name'],
        $r['keys_id'],
        (int) $r['refresh_token_expires_in'],
        (int) $r['access_token_expires_in'],
        (int) $r['pending_login_expires_in'],
        (int) $r['authenticated_login_expires_in'],
        (int) $r['session_expires_in'],
        (int) $r['idle_session_expires_in'],
        $r['scopes'],
        $r['created_at']
      );
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return null;
    }
  }
}
