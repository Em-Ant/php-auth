<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Interfaces\ClientRepository as IRepo;
use AuthServer\Models\Client;
use AuthServer\Repositories\DataSource;

class ClientRepository implements IRepo
{
    private \PDO $db;

    public function __construct(DataSource $data_source)
    {
        $this->db = $data_source->getDb();
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
                $r['require_auth'],
                $r['created_at']
            );
        } catch (\PDOException $e) {
            error_log($e->getMessage());
            return null;
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
                $r['created_at']
            );
        } catch (\PDOException $e) {
            error_log($e->getMessage());
            return null;
        }
    }
}
