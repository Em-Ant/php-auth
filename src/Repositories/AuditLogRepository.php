<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Exceptions\StorageFailed;
use AuthServer\Interfaces\AuditLogRepository as IRepo;
use AuthServer\Models\AuditAction;
use AuthServer\Models\AuditLogEntry;

class AuditLogRepository implements IRepo
{
    use PagedListing;

    private \PDO $db;

    public function __construct(\PDO $db)
    {
        $this->db = $db;
    }

    public function findById(string $id): ?AuditLogEntry
    {
        $r = $this->fetchOne(
            "SELECT * FROM audit_logs WHERE id = :id",
            [':id' => $id],
            "failed to load audit log entry $id"
        );

        return $r === null ? null : self::buildFromData($r);
    }

    public function create(AuditLogEntry $entry): AuditLogEntry
    {
        try {
            $statement = $this->db->prepare(
                "INSERT INTO audit_logs
                    (id, action, actor_type, actor_id, realm_id,
                     target_type, target_id, detail, created_at)
                 VALUES
                    (:id, :action, :actor_type, :actor_id, :realm_id,
                     :target_type, :target_id, :detail, :created_at)"
            );
            $statement->execute([
                ':id' => $entry->getId(),
                ':action' => $entry->getAction()->value,
                ':actor_type' => $entry->getActorType(),
                ':actor_id' => $entry->getActorId(),
                ':realm_id' => $entry->getRealmId(),
                ':target_type' => $entry->getTargetType(),
                ':target_id' => $entry->getTargetId(),
                ':detail' => $entry->getDetail(),
                ':created_at' => $entry->getCreatedAt(),
            ]);

            return $this->findById($entry->getId()) ?? $entry;
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to create audit log entry', 0, $e);
        }
    }

    public function searchAll(
        ?string $action,
        ?string $actorType,
        ?string $targetType,
        ?string $realmId,
        ?string $from,
        ?string $to,
        int $limit,
        int $offset,
    ): array {
        $statement = $this->db->prepare(
            "SELECT *, COUNT(*) OVER() AS result_total
             FROM audit_logs
             WHERE (:action IS NULL OR action = :action)
               AND (:actor_type IS NULL OR actor_type = :actor_type)
               AND (:target_type IS NULL OR target_type = :target_type)
               AND (:realm_id IS NULL OR realm_id = :realm_id)
               AND (:from IS NULL OR created_at >= :from)
               AND (:to IS NULL OR created_at <= :to)
             ORDER BY created_at DESC
             LIMIT :limit OFFSET :offset"
        );
        self::bindNullableString($statement, ':action', $action);
        self::bindNullableString($statement, ':actor_type', $actorType);
        self::bindNullableString($statement, ':target_type', $targetType);
        self::bindNullableString($statement, ':realm_id', $realmId);
        self::bindNullableString($statement, ':from', $from);
        self::bindNullableString($statement, ':to', $to);
        self::bindPageParams($statement, $limit, $offset);

        return $this->fetchPagedPage(
            $statement,
            fn(array $r) => self::buildFromData($r),
            'failed to list audit log entries'
        );
    }

    public function purge(?string $realmId, ?string $olderThan): int
    {
        try {
            $statement = $this->db->prepare(
                "DELETE FROM audit_logs
                 WHERE (:realm_id IS NULL OR realm_id = :realm_id)
                   AND (:older_than IS NULL OR created_at < :older_than)"
            );
            self::bindNullableString($statement, ':realm_id', $realmId);
            self::bindNullableString($statement, ':older_than', $olderThan);
            $statement->execute();

            return $statement->rowCount();
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to purge audit log entries', 0, $e);
        }
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

    private static function buildFromData(array $r): AuditLogEntry
    {
        return new AuditLogEntry(
            $r['id'],
            AuditAction::from($r['action']),
            $r['actor_type'],
            $r['actor_id'],
            $r['realm_id'],
            $r['target_type'],
            $r['target_id'],
            $r['detail'],
            $r['created_at'],
        );
    }
}
