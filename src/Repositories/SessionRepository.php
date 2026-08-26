<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Exceptions\StorageFailed;
use AuthServer\Interfaces\SessionRepository as IRepo;
use AuthServer\Models\Session;

use function AuthServer\getGuid;

class SessionRepository implements IRepo
{
    use PagedListing;

    private \PDO $db;

    public function __construct(\PDO $db)
    {
        $this->db = $db;
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

            if (!$r) {
                return null;
            }

            return self::buildFromData($r);
        } catch (\PDOException $e) {
            throw new StorageFailed("failed to load session by id $id", 0, $e);
        }
    }

    public function create(
        string $realm_id,
        string $user_id,
        string $acr
    ): ?Session {
        try {
            $uid = getGuid();

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

            return $this->findById($uid);
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to create session', 0, $e);
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
            $q->bindValue(':updated_at', gmdate('Y-m-d H:i:s'));
            $q->bindValue(':id', $id);

            return $q->execute();
        } catch (\PDOException $e) {
            throw new StorageFailed("failed to refresh session $id", 0, $e);
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
            throw new StorageFailed("failed to expire session $id", 0, $e);
        }
    }

    public function delete(string $id): bool
    {
        try {
            $q = $this->db->prepare(
                "DELETE FROM sessions WHERE id = :id"
            );
            $q->execute([':id' => $id]);
            return $q->rowCount() > 0;
        } catch (\PDOException $e) {
            throw new StorageFailed("failed to delete session $id", 0, $e);
        }
    }

    public function findAll(?string $realmId = null, ?string $userId = null): array
    {
        try {
            $conditions = [];
            $params = [];

            if ($realmId !== null) {
                $conditions[] = 'realm_id = :realm_id';
                $params[':realm_id'] = $realmId;
            }
            if ($userId !== null) {
                $conditions[] = 'user_id = :user_id';
                $params[':user_id'] = $userId;
            }

            $where = $conditions !== [] ? 'WHERE ' . implode(' AND ', $conditions) : '';
            $statement = $this->db->prepare(
                "SELECT * FROM sessions $where ORDER BY created_at DESC"
            );
            $statement->execute($params);

            return array_map(
                fn(array $r) => self::buildFromData($r),
                $statement->fetchAll()
            );
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to list sessions', 0, $e);
        }
    }

    /**
     * Filtered, paged listing. `total` counts all rows matching the filters,
     * independent of limit/offset.
     *
     * @return array{items: Session[], total: int}
     */
    public function searchAll(?string $realmId, ?string $userId, int $limit, int $offset): array
    {
        $statement = $this->db->prepare(
            "SELECT *, COUNT(*) OVER() AS result_total
             FROM sessions
             WHERE (:realm_id IS NULL OR realm_id = :realm_id)
               AND (:user_id IS NULL OR user_id = :user_id)
             ORDER BY created_at DESC
             LIMIT :limit OFFSET :offset"
        );
        self::bindNullableString($statement, ':realm_id', $realmId);
        self::bindNullableString($statement, ':user_id', $userId);
        self::bindPageParams($statement, $limit, $offset);

        return $this->fetchPagedPage(
            $statement,
            fn(array $r) => self::buildFromData($r),
            'failed to list sessions'
        );
    }

    public function countByUserId(string $userId): int
    {
        return $this->count(
            "SELECT COUNT(*) FROM sessions WHERE user_id = :user_id",
            [':user_id' => $userId],
            'failed to count sessions for user'
        );
    }

    public function countActiveByUserId(string $userId): int
    {
        return $this->count(
            "SELECT COUNT(*) FROM sessions WHERE user_id = :user_id AND status = 'ACTIVE'",
            [':user_id' => $userId],
            'failed to count active sessions for user'
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

    private static function buildFromData(array $r): Session
    {
        return new Session(
            $r['id'],
            $r['realm_id'],
            $r['user_id'],
            $r['acr'],
            $r['created_at'],
            $r['updated_at'],
            $r['status']
        );
    }
}
