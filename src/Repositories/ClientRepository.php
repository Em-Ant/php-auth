<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Exceptions\StorageFailed;
use AuthServer\Interfaces\ClientRepository as IRepo;
use AuthServer\Models\Client;

use function AuthServer\get_guid;

class ClientRepository implements IRepo
{
    private \PDO $db;

    public function __construct(\PDO $db)
    {
        $this->db = $db;
    }

    public function findAll(?string $realmId = null): array
    {
        try {
            if ($realmId === null) {
                $statement = $this->db->query(
                    "SELECT * FROM clients ORDER BY name"
                );
                $rows = $statement->fetchAll();
            } else {
                $statement = $this->db->prepare(
                    "SELECT * FROM clients WHERE realm_id = :realm_id ORDER BY name"
                );
                $statement->execute([':realm_id' => $realmId]);
                $rows = $statement->fetchAll();
            }

            return array_map(fn(array $r) => self::buildFromData($r), $rows);
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to list clients', 0, $e);
        }
    }

    public function create(Client $client): Client
    {
        try {
            $id = $client->getId() !== '' ? $client->getId() : get_guid();

            $statement = $this->db->prepare(
                "INSERT INTO clients (id, name, realm_id, client_secret, uri, require_auth, scope)
                 VALUES (:id, :name, :realm_id, :client_secret, :uri, :require_auth, :scope)"
            );
            $statement->execute(self::clientParams($client, $id));

            return $this->findById($id) ?? $client;
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to create client', 0, $e);
        }
    }

    public function update(Client $client): bool
    {
        try {
            $statement = $this->db->prepare(
                "UPDATE clients SET
                    name = :name,
                    realm_id = :realm_id,
                    client_secret = :client_secret,
                    uri = :uri,
                    require_auth = :require_auth,
                    scope = :scope
                WHERE id = :id"
            );
            return $statement->execute(self::clientParams($client, $client->getId()));
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to update client', 0, $e);
        }
    }

    public function delete(string $id): bool
    {
        try {
            $statement = $this->db->prepare(
                "DELETE FROM clients WHERE id = :id"
            );
            return $statement->execute([':id' => $id]);
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to delete client', 0, $e);
        }
    }

    public function countByRealmId(string $realmId): int
    {
        try {
            $statement = $this->db->prepare(
                "SELECT COUNT(*) FROM clients WHERE realm_id = :realm_id"
            );
            $statement->execute([':realm_id' => $realmId]);
            return (int) $statement->fetchColumn();
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to count clients for realm', 0, $e);
        }
    }

    public function countActiveByRealmId(string $realmId): int
    {
        try {
            $statement = $this->db->prepare(
                "SELECT COUNT(*) FROM clients c
                 WHERE c.realm_id = :realm_id
                 AND EXISTS (
                     SELECT 1 FROM logins l
                     WHERE l.client_id = c.id AND l.status NOT IN ('EXPIRED')
                 )"
            );
            $statement->execute([':realm_id' => $realmId]);
            return (int) $statement->fetchColumn();
        } catch (\PDOException $e) {
            throw new StorageFailed('failed to count active clients for realm', 0, $e);
        }
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

            return self::buildFromData($r);
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

            return self::buildFromData($r);
        } catch (\PDOException $e) {
            throw new StorageFailed("failed to load client by name $name", 0, $e);
        }
    }

    private static function clientParams(Client $client, string $id): array
    {
        return [
            ':id' => $id,
            ':name' => $client->getName(),
            ':realm_id' => $client->getRealmId(),
            ':client_secret' => $client->getClientSecret(),
            ':uri' => $client->getUri(),
            ':require_auth' => $client->requiresAuth() ? 1 : 0,
            ':scope' => $client->getScopeString(),
        ];
    }

    private static function buildFromData(array $r): Client
    {
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
    }
}
