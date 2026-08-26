<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Exceptions\StorageFailed;
use AuthServer\Interfaces\OfflineSessionRepository as IRepo;
use AuthServer\Models\OfflineSession;

class OfflineSessionRepository implements IRepo
{
    use PagedListing;

    private \PDO $db;

    public function __construct(\PDO $db)
    {
        $this->db = $db;
    }

    public function findById(string $id): ?OfflineSession
    {
        return $this->fetchBy(
            'id = :id',
            [':id' => $id],
            "failed to load offline session by id $id"
        );
    }

    public function findByRefreshToken(string $token, string $realmId): ?OfflineSession
    {
        return $this->fetchBy(
            'refresh_token = :token AND realm_id = :realm_id',
            [':token' => $token, ':realm_id' => $realmId],
            'failed to load offline session by refresh token'
        );
    }

    /**
     * $conditions is an internal literal ('id = :id' | 'refresh_token = :token
     * AND realm_id = :realm_id') supplied by findById/findByRefreshToken only —
     * never request input.
     */
    private function fetchBy(string $conditions, array $params, string $errorMessage): ?OfflineSession
    {
        try {
            $statement = $this->db->prepare(
                "SELECT * FROM offline_sessions WHERE $conditions"
            );
            $statement->execute($params);

            $r = $statement->fetch();

            return $r ? self::buildFromData($r) : null;
        } catch (\PDOException $e) {
            throw new StorageFailed($errorMessage, 0, $e);
        }
    }

    public function create(OfflineSession $offlineSession): OfflineSession
    {
        try {
            $q = $this->db->prepare(
                "INSERT INTO offline_sessions (
                    'id', 'realm_id', 'user_id', 'client_id', 'acr', 'scope',
                    'nonce', 'refresh_token', 'authenticated_at', 'status'
                ) VALUES (
                    :id, :realm_id, :user_id, :client_id, :acr, :scope,
                    :nonce, :refresh_token, :authenticated_at, 'ACTIVE'
                )"
            );

            $q->bindValue(':id', $offlineSession->getId());
            $q->bindValue(':realm_id', $offlineSession->getRealmId());
            $q->bindValue(':user_id', $offlineSession->getUserId());
            $q->bindValue(':client_id', $offlineSession->getClientId());
            $q->bindValue(':acr', $offlineSession->getAcr());
            $q->bindValue(':scope', $offlineSession->getScope());
            $q->bindValue(':nonce', $offlineSession->getNonce());
            $q->bindValue(':refresh_token', $offlineSession->getRefreshToken());
            $q->bindValue(
                ':authenticated_at',
                $offlineSession->getAuthenticatedAt()?->format('Y-m-d H:i:s')
            );

            $q->execute();

            $created = $this->findById($offlineSession->getId());
            if ($created === null) {
                throw new StorageFailed('failed to reload created offline session');
            }

            return $created;
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to create offline session', 0, $e);
        }
    }

    public function refresh(
        string $id,
        string $token
    ): bool {
        try {
            $q = $this->db->prepare(
                "UPDATE offline_sessions
                SET updated_at=:updated_at, refresh_token=:token
                WHERE id=:id"
            );
            $q->bindValue(':token', $token);
            $q->bindValue(':updated_at', gmdate('Y-m-d H:i:s'));
            $q->bindValue(':id', $id);

            return $q->execute();
        } catch (\PDOException $e) {
            throw new StorageFailed("failed to refresh offline session $id", 0, $e);
        }
    }

    public function setExpired(
        string $id
    ): bool {
        try {
            $q = $this->db->prepare(
                "UPDATE offline_sessions
                SET status='EXPIRED'
                WHERE id = :id"
            );
            $q->bindValue(':id', $id);

            return $q->execute();
        } catch (\PDOException $e) {
            throw new StorageFailed("failed to expire offline session $id", 0, $e);
        }
    }

    public function countActiveByUserId(string $userId): int
    {
        return $this->count(
            "SELECT COUNT(*) FROM offline_sessions
             WHERE user_id = :user_id AND status = 'ACTIVE'",
            [':user_id' => $userId],
            'failed to count active offline sessions for user'
        );
    }

    public function countActiveByClientId(string $clientId): int
    {
        return $this->count(
            "SELECT COUNT(*) FROM offline_sessions
             WHERE client_id = :client_id AND status = 'ACTIVE'",
            [':client_id' => $clientId],
            'failed to count active offline sessions for client'
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

    public function setExpiredByUserId(string $userId): int
    {
        try {
            $statement = $this->db->prepare(
                "UPDATE offline_sessions
                SET status = 'EXPIRED'
                WHERE user_id = :user_id AND status = 'ACTIVE'"
            );
            $statement->execute([':user_id' => $userId]);

            return $statement->rowCount();
        } catch (\PDOException $e) {
            throw new StorageFailed("failed to expire offline sessions for user $userId", 0, $e);
        }
    }

    public function setExpiredByClientId(string $clientId): int
    {
        try {
            $statement = $this->db->prepare(
                "UPDATE offline_sessions
                SET status = 'EXPIRED'
                WHERE client_id = :client_id AND status = 'ACTIVE'"
            );
            $statement->execute([':client_id' => $clientId]);

            return $statement->rowCount();
        } catch (\PDOException $e) {
            throw new StorageFailed("failed to expire offline sessions for client $clientId", 0, $e);
        }
    }

    public function deleteByUserId(string $userId): int
    {
        try {
            $statement = $this->db->prepare(
                "DELETE FROM offline_sessions WHERE user_id = :user_id"
            );
            $statement->execute([':user_id' => $userId]);

            return $statement->rowCount();
        } catch (\PDOException $e) {
            throw new StorageFailed("failed to delete offline sessions for user $userId", 0, $e);
        }
    }

    public function deleteByClientId(string $clientId): int
    {
        try {
            $statement = $this->db->prepare(
                "DELETE FROM offline_sessions WHERE client_id = :client_id"
            );
            $statement->execute([':client_id' => $clientId]);

            return $statement->rowCount();
        } catch (\PDOException $e) {
            throw new StorageFailed("failed to delete offline sessions for client $clientId", 0, $e);
        }
    }

    /**
     * Filtered, paged listing. `total` counts all rows matching the filters,
     * independent of limit/offset (COUNT(*) OVER()); it is 0 only when the
     * requested page itself is empty.
     *
     * @return array{items: OfflineSession[], total: int}
     */
    public function searchAll(
        ?string $realmId,
        ?string $userId,
        ?string $clientId,
        int $limit,
        int $offset
    ): array {
        $statement = $this->db->prepare(
            "SELECT *, COUNT(*) OVER() AS result_total
             FROM offline_sessions
             WHERE (:realm_id IS NULL OR realm_id = :realm_id)
               AND (:user_id IS NULL OR user_id = :user_id)
               AND (:client_id IS NULL OR client_id = :client_id)
             ORDER BY created_at DESC
             LIMIT :limit OFFSET :offset"
        );
        self::bindNullableString($statement, ':realm_id', $realmId);
        self::bindNullableString($statement, ':user_id', $userId);
        self::bindNullableString($statement, ':client_id', $clientId);
        self::bindPageParams($statement, $limit, $offset);

        return $this->fetchPagedPage(
            $statement,
            fn(array $r) => self::buildFromData($r),
            'failed to search offline sessions'
        );
    }

    private static function buildFromData(array $r): OfflineSession
    {
        return new OfflineSession(
            $r['id'],
            $r['realm_id'],
            $r['user_id'],
            $r['client_id'],
            $r['scope'],
            $r['created_at'],
            $r['acr'],
            $r['nonce'],
            $r['authenticated_at'],
            $r['updated_at'],
            $r['refresh_token'],
            $r['status']
        );
    }
}
