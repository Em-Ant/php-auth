<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Interfaces\SessionRepository as IRepo;
use AuthServer\Lib\Utils;
use AuthServer\Models\Session;
use AuthServer\Repositories\DataSource;

require_once 'src/interfaces/session_repository.php';
require_once 'src/models/session.php';


class SessionRepository implements IRepo
{
  private \PDO $db;

  public function __construct(Datasource $datasource)
  {
    $this->db = $datasource->getDb();
  }

  public function findById(string $id): ?Session
  {
    try {
      $statement = $this->db->prepare(
        "SELECT * FROM sessions WHERE id = :id"
      );
      $statement->bindValue(':id', $id);

      $statement->execute();

      $r = $statement->fetch();

      return self::build_from_data($r);
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return null;
    }
  }

  public function findByCode(string $code): ?Session
  {
    try {
      $statement = $this->db->prepare(
        "SELECT * FROM clients WHERE code = :code"
      );
      $statement->bindValue(':code', $code);

      $statement->execute();

      $r = $statement->fetch();

      if (!$r) return null;

      return self::build_from_data($r);
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return null;
    }
  }

  public function createPending(
    string $client_id,
    string $state,
    string $nonce,
    string $redirect_uri
  ): ?Session {
    try {
      $uid = Utils::get_guid();

      $q = $this->db->prepare(
        "INSERT INTO sessions ('id', 'client_id', 'state', 'nonce', 'redirect_uri')
       VALUES (:id, :client_id, :state, :nonce, :redirect_uri)"
      );

      $q->bindValue(':id', $uid);
      $q->bindValue(':client_id', $client_id);
      $q->bindValue(':state', $state);
      $q->bindValue(':nonce', $nonce);
      $q->bindValue(':redirect_uri', $redirect_uri);

      $q->execute();

      return $this->findById($uid);
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return null;
    }
  }

  public function updateWithUserIdAndCode(
    string $id,
    string $user_id,
    string $code
  ): ?Session {
    try {
      $q = $this->db->prepare(
        "UPDATE sessions 
      SET user_id=:user_id, code=:code, status='AUTHENTICATED'
      WHERE id=:id"
      );
      $q->bindValue(':user_id', $user_id);
      $q->bindValue(':code', $code);
      $q->bindValue(':id', $id);

      $q->execute();

      return $this->findById($id);
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return null;
    }
  }

  public function updateWithRefreshToken(
    string $id,
    string $refresh_token
  ): ?Session {
    try {
      $q = $this->db->prepare(
        "UPDATE sessions 
      SET 'refresh_token' = :refresh_token, 'status' = 'ACTIVE', 
      WHERE 'id' = :id;
      "
      );
      $q->bindValue(':user_id', $refresh_token);
      $q->bindValue(':id', $id);

      $q->execute();

      return $this->findById($id);
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return null;
    }
  }

  private static function build_from_data(array $r): Session
  {
    return new Session(
      $r['id'],
      $r['client_id'],
      $r['state'],
      $r['nonce'],
      $r['redirect_uri'],
      $r['refresh_token'],
      $r['user_id'],
      $r['code'],
      $r['created_at'],
      $r['status'],
    );
  }
}
