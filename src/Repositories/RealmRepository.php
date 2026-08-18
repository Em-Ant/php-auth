<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Exceptions\StorageFailed;
use AuthServer\Interfaces\RealmRepository as IRepo;
use AuthServer\Models\Realm;

class RealmRepository implements IRepo
{
    private \PDO $db;

    public function __construct(\PDO $db)
    {
        $this->db = $db;
    }

    public function findAll(): array
    {
        try {
            $statement = $this->db->query(
                "SELECT * FROM realms ORDER BY name"
            );
            $rows = $statement->fetchAll();

            return array_map(fn(array $r) => self::buildFromData($r), $rows);
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to list realms', 0, $e);
        }
    }

    public function create(Realm $realm): Realm
    {
        try {
            $id = $realm->getId();

            $statement = $this->db->prepare(
                "INSERT INTO realms (
                    id, name, keys_id, refresh_token_expires_in, access_token_expires_in,
                    pending_login_expires_in, authenticated_login_expires_in,
                    session_expires_in, idle_session_expires_in,
                    offline_refresh_token_expires_in, scope
                ) VALUES (
                    :id, :name, :keys_id, :refresh_token_expires_in, :access_token_expires_in,
                    :pending_login_expires_in, :authenticated_login_expires_in,
                    :session_expires_in, :idle_session_expires_in,
                    :offline_refresh_token_expires_in, :scope
                )"
            );
            $statement->execute(self::realmParams($realm, $id));

            return $this->findById($id) ?? $realm;
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to create realm', 0, $e);
        }
    }

    public function update(Realm $realm): bool
    {
        try {
            $statement = $this->db->prepare(
                "UPDATE realms SET
                    name = :name,
                    keys_id = :keys_id,
                    refresh_token_expires_in = :refresh_token_expires_in,
                    access_token_expires_in = :access_token_expires_in,
                    pending_login_expires_in = :pending_login_expires_in,
                    authenticated_login_expires_in = :authenticated_login_expires_in,
                    session_expires_in = :session_expires_in,
                    idle_session_expires_in = :idle_session_expires_in,
                    offline_refresh_token_expires_in = :offline_refresh_token_expires_in,
                    scope = :scope
                WHERE id = :id"
            );
            return $statement->execute(self::realmParams($realm, $realm->getId()));
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to update realm', 0, $e);
        }
    }

    public function delete(string $id): bool
    {
        try {
            $statement = $this->db->prepare(
                "DELETE FROM realms WHERE id = :id"
            );
            return $statement->execute([':id' => $id]);
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to delete realm', 0, $e);
        }
    }

    public function findById(string $id): ?Realm
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

            return self::buildFromData($r);
        } catch (\PDOException $e) {
            throw new StorageFailed("failed to load realm by id $id", 0, $e);
        }
    }

    public function findByName(string $name): ?Realm
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

            return self::buildFromData($r);
        } catch (\PDOException $e) {
            throw new StorageFailed("failed to load realm by name $name", 0, $e);
        }
    }

    private static function realmParams(Realm $realm, string $id): array
    {
        return [
            ':id' => $id,
            ':name' => $realm->getName(),
            ':keys_id' => $realm->getKeysId(),
            ':refresh_token_expires_in' => $realm->getRefreshTokenExpiresIn(),
            ':access_token_expires_in' => $realm->getAccessTokenExpiresIn(),
            ':pending_login_expires_in' => $realm->getPendingLoginExpiresIn(),
            ':authenticated_login_expires_in' => $realm->getAuthenticatedLoginExpiresIn(),
            ':session_expires_in' => $realm->getSessionExpiresIn(),
            ':idle_session_expires_in' => $realm->getIdleSessionExpiresIn(),
            ':offline_refresh_token_expires_in' => $realm->getOfflineRefreshTokenExpiresIn(),
            ':scope' => implode(' ', $realm->getScope()),
        ];
    }

    private static function buildFromData(array $r): Realm
    {
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
            $r['scope'],
            $r['created_at'],
            (int) ($r['offline_refresh_token_expires_in'] ?? 2592000)
        );
    }
}
