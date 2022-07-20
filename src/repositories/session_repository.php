<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Interfaces\SessionRepository as IRepo;
use AuthServer\Lib\Utils;
use AuthServer\Models\Session;
use AuthServer\Repositories\DataSource;

require_once 'src/interfaces/session_repository.php';
require_once 'src/models/session.php';
require_once 'src/lib/utils.php';


class SessionRepository implements IRepo
{
  private \PDO $db;

  public function __construct(DataSource $data_source)
  {
    $this->db = $data_source->getDb();
  }

  public function find_by_id(string $id): ?Session
  {
    try {
      $statement = $this->db->prepare(
        "SELECT * FROM sessions WHERE id = :id"
      );
      $statement->bindValue(':id', $id);

      $statement->execute();

      $r = $statement->fetch();

      if (!$r) {
        return null;
      }

      return self::build_from_data($r);
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return null;
    }
  }

  public function create(
    string $realm_id,
    string $user_id,
    string $acr
  ): ?Session {
    try {
      $uid = Utils::get_guid();

      $q = $this->db->prepare(
        "INSERT INTO sessions (
          'id', 'realm_id', 'user_id', 'acr'
        ) VALUES (:id, :realm_id, :user_id, :acr)"
      );

      $q->bindValue(':id', $uid);
      $q->bindValue(':realm_id', $realm_id);
      $q->bindValue(':user_id', $user_id);
      $q->bindValue(':acr', $acr);

      $q->execute();

      return $this->find_by_id($uid);
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return null;
    }
  }

  public function refresh(
    string $id
  ): bool {
    try {
      $q = $this->db->prepare(
        "UPDATE sessions 
      SET updated_at=:updated_at
      WHERE id=:id"
      );
      $q->bindValue(':updated_at', date_create()->format('Y-m-d H:i:s'));
      $q->bindValue(':id', $id);

      return $q->execute();
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return false;
    }
  }

  public function set_expired(
    string $id
  ): bool {
    try {
      $q = $this->db->prepare(
        "UPDATE sessions 
      SET status='EXPIRED' 
      WHERE id = :id"
      );
      $q->bindValue(':id', $id);

      return $q->execute();
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return false;
    }
  }

  private static function build_from_data(array $r): Session
  {
    return new Session(
      $r['id'],
      $r['realm_id'],
      $r['acr'],
      $r['user_id'],
      $r['created_at'],
      $r['updated_at'],
      $r['status']
    );
  }
}

  /*

    public function find_by_code(string $code): ?Session
  {
    try {
      $statement = $this->db->prepare(
        "SELECT * FROM sessions WHERE code = :code"
      );
      $statement->bindValue(':code', $code);

      $statement->execute();

      $r = $statement->fetch();

      if (!$r) {
        return null;
      }

      return self::build_from_data($r);
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return null;
    }
  }

  public function find_by_refresh_token(string $token): ?Session
  {
    try {
      $statement = $this->db->prepare(
        "SELECT * FROM sessions WHERE refresh_token = :token"
      );
      $statement->bindValue(':token', $token);

      $statement->execute();

      $r = $statement->fetch();

      if (!$r) {
        return null;
      }

      return self::build_from_data($r);
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return null;
    }
  }

  public function setActive(
    string $id,
    string $refresh_token
  ): bool {
    try {
      $q = $this->db->prepare(
        "UPDATE sessions 
      SET refresh_token=:refresh_token, status='ACTIVE' 
      WHERE id = :id"
      );
      $q->bindValue(':refresh_token', $refresh_token);
      $q->bindValue(':id', $id);

      return $q->execute();
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return false;
    }
  }

  public function updateRefreshToken(
    string $id,
    string $refresh_token
  ): bool {
    try {
      $q = $this->db->prepare(
        "UPDATE sessions 
      SET refresh_token=:refresh_token
      WHERE id = :id"
      );
      $q->bindValue(':refresh_token', $refresh_token);
      $q->bindValue(':id', $id);

      return $q->execute();
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return false;
    }
  }
  */