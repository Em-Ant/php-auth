<?php

declare(strict_types=1);

namespace AuthServer\Tests\Support;

/**
 * Simulates a database outage: every statement preparation fails. Used to
 * verify that repositories surface storage failures instead of returning
 * null/false (which callers would misread as "not found" → 400s).
 */
class FailingPdo extends \PDO
{
    public function __construct()
    {
        parent::__construct('sqlite::memory:');
    }

    #[\Override]
    public function prepare(string $query, array $options = []): \PDOStatement|false
    {
        throw new \PDOException('simulated database outage');
    }
}
