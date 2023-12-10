<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Interfaces\LoginRepository as IRepo;
use Emant\BrowniePhp\Utils;;

use AuthServer\Models\Login;
use AuthServer\Repositories\DataSource;



class LoginRepository implements IRepo
{
  private \PDO $db;

  public function __construct(DataSource $data_source)
  {
    $this->db = $data_source->getDb();
  }

  public function find_by_id(string $id): ?Login
  {
    try {
      $statement = $this->db->prepare(
        "SELECT * FROM logins WHERE id = :id"
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

  public function find_by_code(string $code): ?Login
  {
    try {
      $statement = $this->db->prepare(
        "SELECT * FROM logins WHERE code = :code"
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

  public function find_by_refresh_token(string $token): ?Login
  {
    try {
      $statement = $this->db->prepare(
        "SELECT * FROM logins WHERE refresh_token = :token"
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

  public function create_pending(
    string $client_id,
    string $state,
    string $nonce,
    string $scope,
    string $redirect_uri,
    string $response_mode,
    ?string $code_challenge
  ): ?Login {
    try {
      $uid = Utils::get_guid();

      $q = $this->db->prepare(
        "INSERT INTO logins (
          'id', 'client_id', 'state', 'nonce', 'scope', 
          'redirect_uri', 'response_mode', 'code_challenge', 'status'
        ) VALUES (
          :id, :client_id, :state, :nonce, :scope, 
          :redirect_uri, :response_mode, :code_challenge, 'PENDING'
        )"
      );

      $q->bindValue(':id', $uid);
      $q->bindValue(':client_id', $client_id);
      $q->bindValue(':state', $state);
      $q->bindValue(':nonce', $nonce);
      $q->bindValue(':scope', $scope);
      $q->bindValue(':redirect_uri', $redirect_uri);
      $q->bindValue(':response_mode', $response_mode);
      $q->bindValue(':code_challenge', $code_challenge);

      $q->execute();

      return $this->find_by_id($uid);
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return null;
    }
  }

  public function create_authenticated(
    string $client_id,
    string $session_id,
    string $state,
    string $nonce,
    string $scope,
    string $redirect_uri,
    string $response_mode,
    string $code,
    ?string $code_challenge
  ): ?Login {
    try {
      $uid = Utils::get_guid();

      $q = $this->db->prepare(
        "INSERT INTO logins (
          'id', 'client_id', 'session_id', 'state', 'nonce', 'scope', 
          'redirect_uri', 'response_mode', 'code', 'code_challenge', 'status', authenticated_at
        ) VALUES (
          :id, :client_id, :session_id, :state, :nonce, :scope, 
          :redirect_uri, :response_mode, :code, :code_challenge, 'AUTHENTICATED', :timestamp
        )"
      );

      $q->bindValue(':id', $uid);
      $q->bindValue(':client_id', $client_id);
      $q->bindValue(':session_id', $session_id);
      $q->bindValue(':state', $state);
      $q->bindValue(':nonce', $nonce);
      $q->bindValue(':scope', $scope);
      $q->bindValue(':redirect_uri', $redirect_uri);
      $q->bindValue(':response_mode', $response_mode);
      $q->bindValue(':timestamp', gmdate('Y-m-d H:i:s'));
      $q->bindValue(':code', $code);
      $q->bindValue(':code_challenge', $code_challenge);

      $q->execute();

      return $this->find_by_id($uid);
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return null;
    }
  }

  public function set_authenticated(
    string $id,
    string $session_id,
    string $code
  ): bool {
    try {
      $q = $this->db->prepare(
        "UPDATE logins 
      SET session_id=:session_id, code=:code, 
        authenticated_at=:timestamp, 
        status='AUTHENTICATED' 
      WHERE id = :id"
      );
      $q->bindValue(':code', $code);
      $q->bindValue(':session_id', $session_id);
      $q->bindValue(':timestamp', gmdate('Y-m-d H:i:s'));
      $q->bindValue(':id', $id);

      return $q->execute();
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return false;
    }
  }

  public function set_active(
    string $id,
    string $refresh_token
  ): bool {
    try {
      $q = $this->db->prepare(
        "UPDATE logins 
      SET refresh_token=:refresh_token, status='ACTIVE', updated_at=:timestamp
      WHERE id = :id"
      );
      $q->bindValue(':refresh_token', $refresh_token);
      $q->bindValue(':timestamp', gmdate('Y-m-d H:i:s'));
      $q->bindValue(':id', $id);

      return $q->execute();
    } catch (\PDOException $e) {
      error_log($e->getMessage());
      return false;
    }
  }

  public function refresh(
    string $id,
    string $token
  ): bool {
    try {
      $q = $this->db->prepare(
        "UPDATE logins 
      SET updated_at=:updated_at, refresh_token=:token  
      WHERE id=:id"
      );
      $q->bindValue(':token', $token);
      $q->bindValue(':updated_at', gmdate('Y-m-d H:i:s'));
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
        "UPDATE logins 
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

  private static function build_from_data(array $r): Login
  {
    return new Login(
      $r['id'],
      $r['client_id'],
      $r['state'],
      $r['nonce'],
      $r['scope'],
      $r['redirect_uri'],
      $r['response_mode'],
      $r['created_at'],
      $r['session_id'],
      $r['authenticated_at'],
      $r['code'],
      $r['code_challenge'],
      $r['updated_at'],
      $r['refresh_token'],
      $r['status']
    );
  }
}
