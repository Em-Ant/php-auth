<?php

declare(strict_types=1);

namespace AuthServer\Services;

/**
 * Wraps a closure in a transaction on the owning PDO connection ($this->db).
 *
 * Joins an already-active transaction instead of nesting: SQLite has no
 * nested transactions, and the services sharing this trait also share the
 * PDO connection, so the transaction is committed/rolled back exactly once
 * by whoever started it.
 */
trait RunsTransactions
{
    private function transact(\Closure $work): mixed
    {
        $ownsTransaction = !$this->db->inTransaction();
        if ($ownsTransaction) {
            $this->db->beginTransaction();
        }

        try {
            $result = $work();
            if ($ownsTransaction) {
                $this->db->commit();
            }
            return $result;
        } catch (\Throwable $e) {
            if ($ownsTransaction) {
                $this->db->rollBack();
            }
            throw $e;
        }
    }
}
