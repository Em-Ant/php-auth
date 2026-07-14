<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Models;

use AuthServer\Models\LoginStatus;
use PHPUnit\Framework\TestCase;

class LoginStatusTest extends TestCase
{
    public function testHasFourCases(): void
    {
        self::assertCount(4, LoginStatus::cases());
    }

    public function testPendingValue(): void
    {
        self::assertSame('PENDING', LoginStatus::Pending->value);
    }

    public function testAuthenticatedValue(): void
    {
        self::assertSame('AUTHENTICATED', LoginStatus::Authenticated->value);
    }

    public function testActiveValue(): void
    {
        self::assertSame('ACTIVE', LoginStatus::Active->value);
    }

    public function testExpiredValue(): void
    {
        self::assertSame('EXPIRED', LoginStatus::Expired->value);
    }
}
