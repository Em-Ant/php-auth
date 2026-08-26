<?php

declare(strict_types=1);

namespace AuthServer\Repositories;

use AuthServer\Exceptions\StorageFailed;

/**
 * Shared plumbing for filtered, paged listings backed by a
 * `COUNT(*) OVER() AS result_total` query.
 */
trait PagedListing
{
    /**
     * @param callable(array): mixed $mapRow
     *
     * @return array{items: list<mixed>, total: int}
     */
    private function fetchPagedPage(\PDOStatement $statement, callable $mapRow, string $errorMessage): array
    {
        try {
            $statement->execute();

            $rows = $statement->fetchAll();

            return [
                'items' => array_map($mapRow, $rows),
                'total' => $rows === [] ? 0 : (int) $rows[0]['result_total'],
            ];
        } catch (\PDOException $e) {
            throw new StorageFailed($errorMessage, 0, $e);
        }
    }

    private static function bindNullableString(\PDOStatement $statement, string $key, ?string $value): void
    {
        $type = $value === null ? \PDO::PARAM_NULL : \PDO::PARAM_STR;
        $statement->bindValue($key, $value, $type);
    }

    private static function bindPageParams(\PDOStatement $statement, int $limit, int $offset): void
    {
        $statement->bindValue(':limit', $limit, \PDO::PARAM_INT);
        $statement->bindValue(':offset', $offset, \PDO::PARAM_INT);
    }
}
