<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Repositories;

use AuthServer\Repositories\DataSource;
use PHPUnit\Framework\TestCase;

class DataSourceTest extends TestCase
{
    public function testCreateInstanceInjectsPdo(): void
    {
        $pdo = new \PDO('sqlite::memory:');
        DataSource::createInstance($pdo);

        $ds = DataSource::getInstance();
        self::assertSame($pdo, $ds->getDb());
    }

    public function testGetInstanceReturnsSameInstance(): void
    {
        $pdo = new \PDO('sqlite::memory:');
        DataSource::createInstance($pdo);

        $ds1 = DataSource::getInstance();
        $ds2 = DataSource::getInstance();
        self::assertSame($ds1, $ds2);
    }
}
