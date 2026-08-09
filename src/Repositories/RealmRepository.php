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
                $r['created_at']
            );
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
                $r['created_at']
            );
        } catch (\PDOException $e) {
            throw new StorageFailed("failed to load realm by name $name", 0, $e);
        }
    }
}
