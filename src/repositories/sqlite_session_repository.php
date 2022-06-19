<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Interfaces\SessionRepository as IRepo;
use AuthServer\Lib\Utils;
use AuthServer\Models\Session;
use AuthServer\Repositories\DataSource;

require_once 'src/interfaces/session_repository.php';

class SQLiteSessionRepository implements IRepo
{
  private $db;

  public function __construct(Datasource $datasource)
  {
    $this->db = $datasource->getDb();
  }

  public function findById(string $id): ?Session
  {
    $query = $this->db->prepare(
      "SELECT * FROM sessions WHERE id = :id"
    );
    $query->bindValue(':id', $id, SQLITE3_TEXT);

    $results = $query->execute();
    if ($results === FALSE) {
      return null;
    }

    $r = $results->fetchArray(SQLITE3_ASSOC);

    if ($r === FALSE) {
      return null;
    }

    return self::build_from_data($r);
  }

  public function findByCode(string $code): ?Session
  {
    $query = $this->db->prepare(
      "SELECT * FROM clients WHERE code = :code"
    );
    $query->bindValue(':code', $code, SQLITE3_TEXT);

    $results = $query->execute();
    if ($results === false) {
      return null;
    }

    $r = $results->fetchArray(SQLITE3_ASSOC);
    if ($r === false) {
      return null;
    }

    return self::build_from_data($r);
  }

  public function createPending(
    string $client_id,
    string $state,
    string $nonce,
    string $redirect_uri
  ): ?Session {
    $uid = Utils::get_guid();

    $q = $this->db->prepare(
      "INSERT INTO sessions ('id', 'client_id', 'state', 'nonce', 'redirect_uri')
       VALUES (:id, :client_id, :state, :nonce, :redirect_uri)"
    );

    $q->bindValue(':id', $uid, SQLITE3_TEXT);
    $q->bindValue(':client_id', $client_id, SQLITE3_TEXT);
    $q->bindValue(':state', $state, SQLITE3_TEXT);
    $q->bindValue(':nonce', $nonce, SQLITE3_TEXT);
    $q->bindValue(':redirect_uri', $redirect_uri, SQLITE3_TEXT);

    $q->execute();

    return $this->findById($uid);
  }

  public function updateWithUserIdAndCode(
    string $id,
    string $user_id,
    string $code
  ): ?Session {
    $q = $this->db->prepare(
      "UPDATE sessions 
      SET 'user_id' = :user_id, 'code' = :code, 'status' = 'AUTHENTICATED', 
      WHERE 'id' = :id;
      "
    );
    $q->bindValue(':user_id', $user_id, SQLITE3_TEXT);
    $q->bindValue(':code', $code, SQLITE3_TEXT);
    $q->bindValue(':id', $id, SQLITE3_TEXT);

    $q->execute();

    return $this->findById($id);
  }

  public function updateWithRefreshToken(
    string $id,
    string $refresh_token
  ): ?Session {
    $q = $this->db->prepare(
      "UPDATE sessions 
      SET 'refresh_token' = :refresh_token, 'status' = 'ACTIVE', 
      WHERE 'id' = :id;
      "
    );
    $q->bindValue(':user_id', $refresh_token, SQLITE3_TEXT);
    $q->bindValue(':id', $id, SQLITE3_TEXT);

    $q->execute();

    return $this->findById($id);
  }

  private static function build_from_data(array $r): Session
  {
    return new Session(
      (string) $r['id'],
      $r['client_id'],
      $r['state'],
      $r['nonce'],
      $r['redirect_uri'],
      $r['refresh_token'],
      $r['user_id'],
      $r['code'],
      \DateTime::createFromFormat('Y-m-d H:i:s', $r['created_at']),
      $r['status'],
    );
  }
}
