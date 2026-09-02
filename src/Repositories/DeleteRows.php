<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Exceptions\StorageFailed;

/**
 * Shared bolt-on for repository DELETE statements: one try/catch wrapper for
 * the prepare/execute/rowCount shape, with a single StorageFailed translation
 * point. SQL must only reference bound parameters — never user input.
 */
trait DeleteRows
{
    private function deleteWhere(string $sql, array $params, string $errorMessage): int
    {
        try {
            $statement = $this->db->prepare($sql);
            $statement->execute($params);

            return $statement->rowCount();
        } catch (\PDOException $e) {
            throw new StorageFailed($errorMessage, 0, $e);
        }
    }
}
