<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Exceptions\StorageFailed;
use AuthServer\Interfaces\ClientRepository as IRepo;
use AuthServer\Models\Client;

use function AuthServer\getGuid;

class ClientRepository implements IRepo
{
    use PagedListing;

    private \PDO $db;

    public function __construct(\PDO $db)
    {
        $this->db = $db;
    }

    /**
     * Filtered, paged listing. `total` counts all rows matching the filters,
     * independent of limit/offset.
     *
     * @return array{items: Client[], total: int}
     */
    public function searchAll(?string $realmId, int $limit, int $offset): array
    {
        $statement = $this->db->prepare(
            "SELECT *, COUNT(*) OVER() AS result_total
             FROM clients
             WHERE (:realm_id IS NULL OR realm_id = :realm_id)
             ORDER BY name
             LIMIT :limit OFFSET :offset"
        );
        self::bindNullableString($statement, ':realm_id', $realmId);
        self::bindPageParams($statement, $limit, $offset);

        return $this->fetchPagedPage(
            $statement,
            fn(array $r) => self::buildFromData($r),
            'failed to list clients'
        );
    }

    public function create(Client $client): Client
    {
        try {
            $id = $client->getId() !== '' ? $client->getId() : getGuid();

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

    public function findById(string $id): ?Client
    {
        $r = $this->fetchOne(
            "SELECT * FROM clients WHERE id = :id",
            [':id' => $id],
            "failed to load client by id $id"
        );

        return $r === null ? null : self::buildFromData($r);
    }

    public function findByName(string $name): ?Client
    {
        $r = $this->fetchOne(
            "SELECT * FROM clients WHERE name = :name",
            [':name' => $name],
            "failed to load client by name $name"
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
