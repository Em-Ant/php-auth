<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Interfaces\ClientRepository as IClientRepo;
use AuthServer\Models\Client;
use AuthServer\Repositories\DataSource;

require_once 'src/interfaces/client_repository.php';

class SQLiteClientRepository implements IClientRepo
{
    private $db;

    public function __construct(Datasource $datasource)
    {
        $this->db = $datasource->getDb();
    }

    public function findClientById(string $id): ?Client
    {
        $query = $this->db->prepare(
            "SELECT * FROM clients WHERE id = :id"
        );
        $query->bindValue(':id', $id, SQLITE3_INTEGER);

        $results = $query->execute();
        if ($results === false) {
            return null;
        }

        $r = $results->fetchArray(SQLITE3_ASSOC);
        if ($r === false) {
            return null;
        }

        echo($r['uri']);
        return new Client((string) $r['id'], $r['client_id'], $r['uri'], $r['client_secret']);
    }

    public function findClientByClientId(string $client_id): ?Client
    {
        $query = $this->db->prepare(
            "SELECT * FROM clients WHERE client_id = :id"
        );
        $query->bindValue(':id', $client_id, SQLITE3_TEXT);

        $results = $query->execute();
        if ($results === false) {
            return null;
        }

        $r = $results->fetchArray(SQLITE3_ASSOC);
        if ($r === false) {
            return null;
        }

        return new Client((string) $r['id'], $r['client_id'], $r['uri'], $r['client_secret']);
    }
}
