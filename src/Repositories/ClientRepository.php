<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Exceptions\StorageFailed;
use AuthServer\Interfaces\ClientRepository as IRepo;
use AuthServer\Models\Client;

class ClientRepository implements IRepo
{
    private \PDO $db;

    public function __construct(\PDO $db)
    {
        $this->db = $db;
    }

    public function findById(string $id): ?Client
    {
        try {
            $statement = $this->db->prepare(
                "SELECT * FROM clients WHERE id = :id"
            );
            $statement->bindValue(':id', $id);

            $statement->execute();

            $r = $statement->fetch();

            if (!$r) {
                return null;
            }

            return new Client(
                $r['id'],
                $r['name'],
                $r['realm_id'],
                $r['client_secret'],
                $r['uri'],
                (bool) $r['require_auth'],
                $r['created_at'],
                $r['scope']
            );
        } catch (\PDOException $e) {
            throw new StorageFailed("failed to load client by id $id", 0, $e);
        }
    }

    public function findByName(string $name): ?Client
    {
        try {
            $statement = $this->db->prepare(
                "SELECT * FROM clients WHERE name = :name"
            );
            $statement->bindValue(':name', $name);

            $statement->execute();

            $r = $statement->fetch();

            if (!$r) {
                return null;
            }

            return new Client(
                $r['id'],
                $r['name'],
                $r['realm_id'],
                $r['client_secret'],
                $r['uri'],
                (bool) $r['require_auth'],
                $r['created_at'],
                $r['scope']
            );
        } catch (\PDOException $e) {
            throw new StorageFailed("failed to load client by name $name", 0, $e);
        }
    }
}
