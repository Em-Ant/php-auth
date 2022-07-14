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

  public function __construct(Datasource $datasource)
  {
    $this->db = $datasource->getDb();
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

      if (!$r) return null;

      return self::build_from_data($r);
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return null;
    }
  }

  public function find_by_code(string $code): ?Session
  {
    try {
      $statement = $this->db->prepare(
        "SELECT * FROM sessions WHERE code = :code"
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

  public function ffind_by_refresh_token(string $token): ?Session
  {
    try {
      $statement = $this->db->prepare(
        "SELECT * FROM sessions WHERE refresh_token = :token"
      );
      $statement->bindValue(':token', $token);

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
        "INSERT INTO sessions (
          'id', 'client_id', 'state', 'nonce', 'session_state','redirect_uri'
        ) VALUES (:id, :client_id, :state, :nonce, :session_state, :redirect_uri)"
      );

      $q->bindValue(':id', $uid);
      $q->bindValue(':client_id', $client_id);
      $q->bindValue(':state', $state);
      $q->bindValue(':nonce', $nonce);
      $q->bindValue(':session_state', Utils::get_guid());
      $q->bindValue(':redirect_uri', $redirect_uri);

      $q->execute();

      return $this->find_by_id($uid);
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return null;
    }
  }

  public function setAuthenticated(
    string $id,
    string $user_id,
    string $code
  ): bool {
    try {
      $q = $this->db->prepare(
        "UPDATE sessions 
      SET user_id=:user_id, code=:code, authenticated_at=:auth_time, status='AUTHENTICATED'
      WHERE id=:id"
      );
      $q->bindValue(':user_id', $user_id);
      $q->bindValue(':code', $code);
      $q->bindValue(':auth_time', date_create()->format('Y-m-d H:i:s'));
      $q->bindValue(':id', $id);

      return $q->execute();
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return false;
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

  public function setExpired(
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

  private static function build_from_data(array $r): Session
  {
    return new Session(
      $r['id'],
      $r['client_id'],
      $r['state'],
      $r['nonce'],
      $r['session_state'],
      $r['redirect_uri'],
      $r['refresh_token'],
      $r['user_id'],
      $r['code'],
      $r['created_at'],
      $r['authenticated_at'],
      $r['status'],
    );
  }
}
