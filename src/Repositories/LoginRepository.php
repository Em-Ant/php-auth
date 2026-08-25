<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Exceptions\StorageFailed;
use AuthServer\Interfaces\LoginRepository as IRepo;
use AuthServer\Models\Login;

use function AuthServer\getGuid;
use function AuthServer\sql_now;

class LoginRepository implements IRepo
{
    private \PDO $db;

    public function __construct(\PDO $db)
    {
        $this->db = $db;
    }

    public function findById(string $id): ?Login
    {
        $r = $this->fetchOne(
            "SELECT * FROM logins WHERE id = :id",
            [':id' => $id],
            "failed to load login by id $id"
        );

        return $r === null ? null : self::buildFromData($r);
    }

    public function findByCode(string $code, string $realmId): ?Login
    {
        return $this->findBy('code', $code, $realmId);
    }

    public function findByRefreshToken(string $token, string $realmId): ?Login
    {
        return $this->findBy('refresh_token', $token, $realmId);
    }

    /**
     * $column is an internal literal ('code' | 'refresh_token') supplied by
     * findByCode/findByRefreshToken only — never request input.
     */
    private function findBy(string $column, string $value, string $realmId): ?Login
    {
        $r = $this->fetchOne(
            "SELECT l.* FROM logins l
             JOIN clients c ON l.client_id = c.id
             WHERE l.$column = :value AND c.realm_id = :realm_id",
            [':value' => $value, ':realm_id' => $realmId],
            "failed to load login by $column"
        );

        return $r === null ? null : self::buildFromData($r);
    }

    private function fetchOne(string $sql, array $params, string $errorMessage): ?array
    {
        try {
            $statement = $this->db->prepare($sql);
            $statement->execute($params);

            $r = $statement->fetch();

            return $r === false ? null : $r;
        } catch (\PDOException $e) {
            throw new StorageFailed($errorMessage, 0, $e);
        }
    }

    public function createPending(
        string $client_id,
        string $state,
        string $nonce,
        string $scope,
        string $redirect_uri,
        string $response_mode,
        ?string $code_challenge,
        ?string $csrf_token
    ): ?Login {
        try {
            $uid = getGuid();

            $q = $this->db->prepare(
                "INSERT INTO logins (
          'id', 'client_id', 'state', 'nonce', 'scope',
          'redirect_uri', 'response_mode', 'code_challenge', 'csrf_token', 'status'
        ) VALUES (
          :id, :client_id, :state, :nonce, :scope,
          :redirect_uri, :response_mode, :code_challenge, :csrf_token, 'PENDING'
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
            $q->bindValue(':csrf_token', $csrf_token);

            $q->execute();

            return $this->findById($uid);
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to create pending login', 0, $e);
        }
    }

    public function createAuthenticated(
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
            $uid = getGuid();

            $q = $this->db->prepare(
                "INSERT INTO logins (
          'id', 'client_id', 'session_id', 'state', 'nonce', 'scope',
          'redirect_uri', 'response_mode', 'code', 'code_challenge', 'status', authenticated_at
        ) VALUES (
          :id, :client_id, :session_id, :state, :nonce, :scope,
          :redirect_uri, :response_mode, :code, :code_challenge, 'AUTHENTICATED', :authenticated_at
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
            $q->bindValue(':authenticated_at', sql_now());
            $q->bindValue(':code', $code);
            $q->bindValue(':code_challenge', $code_challenge);

            $q->execute();

            return $this->findById($uid);
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to create authenticated login', 0, $e);
        }
    }

    public function setAuthenticated(
        string $id,
        string $session_id,
        string $code
    ): bool {
        try {
            $q = $this->db->prepare(
                "UPDATE logins
      SET session_id=:session_id, code=:code,
        authenticated_at=:authenticated_at,
        status='AUTHENTICATED'
      WHERE id = :id"
            );
            $q->bindValue(':code', $code);
            $q->bindValue(':session_id', $session_id);
            $q->bindValue(':authenticated_at', sql_now());
            $q->bindValue(':id', $id);

            return $q->execute();
        } catch (\PDOException $e) {
            throw new StorageFailed("failed to persist authenticated status for login $id", 0, $e);
        }
    }

    public function setActive(
        string $id,
        string $refresh_token
    ): bool {
        try {
            $q = $this->db->prepare(
                "UPDATE logins
      SET refresh_token=:refresh_token, status='ACTIVE', updated_at=:updated_at
      WHERE id = :id"
            );
            $q->bindValue(':refresh_token', $refresh_token);
            $q->bindValue(':updated_at', sql_now());
            $q->bindValue(':id', $id);

            return $q->execute();
        } catch (\PDOException $e) {
            throw new StorageFailed("failed to activate login $id", 0, $e);
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
            $q->bindValue(':updated_at', sql_now());
            $q->bindValue(':id', $id);

            return $q->execute();
        } catch (\PDOException $e) {
            throw new StorageFailed("failed to refresh login $id", 0, $e);
        }
    }

    public function setExpired(
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
            throw new StorageFailed("failed to expire login $id", 0, $e);
        }
    }

    public function delete(string $id): bool
    {
        try {
            $q = $this->db->prepare(
                "DELETE FROM logins WHERE id = :id"
            );
            return $q->execute([':id' => $id]);
        } catch (\PDOException $e) {
            throw new StorageFailed("failed to delete login $id", 0, $e);
        }
    }

    public function deleteBySessionId(string $sessionId): int
    {
        try {
            $q = $this->db->prepare(
                "DELETE FROM logins WHERE session_id = :session_id"
            );
            $q->execute([':session_id' => $sessionId]);
            return $q->rowCount();
        } catch (\PDOException $e) {
            throw new StorageFailed("failed to delete logins for session $sessionId", 0, $e);
        }
    }

    public function findAll(?string $realmId = null, ?string $clientId = null): array
    {
        try {
            $conditions = [];
            $params = [];

            if ($realmId !== null) {
                $conditions[] = 'c.realm_id = :realm_id';
                $params[':realm_id'] = $realmId;
            }
            if ($clientId !== null) {
                $conditions[] = 'l.client_id = :client_id';
                $params[':client_id'] = $clientId;
            }

            $where = $conditions !== [] ? 'WHERE ' . implode(' AND ', $conditions) : '';
            $statement = $this->db->prepare(
                "SELECT l.* FROM logins l
                 LEFT JOIN clients c ON l.client_id = c.id
                 $where
                 ORDER BY l.created_at DESC"
            );
            $statement->execute($params);

            return array_map(
                fn(array $r) => self::buildFromData($r),
                $statement->fetchAll()
            );
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to list logins', 0, $e);
        }
    }

    public function countByClientId(string $clientId): int
    {
        return $this->count(
            "SELECT COUNT(*) FROM logins WHERE client_id = :client_id",
            [':client_id' => $clientId],
            'failed to count logins for client'
        );
    }

    public function countActiveByClientId(string $clientId): int
    {
        return $this->count(
            "SELECT COUNT(*) FROM logins WHERE client_id = :client_id AND status NOT IN ('EXPIRED')",
            [':client_id' => $clientId],
            'failed to count active logins for client'
        );
    }

    private function count(string $sql, array $params, string $errorMessage): int
    {
        try {
            $statement = $this->db->prepare($sql);
            $statement->execute($params);

            return (int) $statement->fetchColumn();
        } catch (\PDOException $e) {
            throw new StorageFailed($errorMessage, 0, $e);
        }
    }

    private static function buildFromData(array $r): Login
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
            $r['csrf_token'],
            $r['updated_at'],
            $r['refresh_token'],
            $r['status']
        );
    }
}
