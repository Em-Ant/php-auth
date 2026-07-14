<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Models;

use AuthServer\Models\LoginEvent;
use PHPUnit\Framework\TestCase;

class LoginEventTest extends TestCase
{
    public function testHasFiveCases(): void
    {
        self::assertCount(5, LoginEvent::cases());
    }

    public function testAuthenticateValue(): void
    {
        self::assertSame('authenticate', LoginEvent::Authenticate->value);
    }

    public function testActivateValue(): void
    {
        self::assertSame('activate', LoginEvent::Activate->value);
    }

    public function testRefreshValue(): void
    {
        self::assertSame('refresh', LoginEvent::Refresh->value);
    }

    public function testExpireValue(): void
    {
        self::assertSame('expire', LoginEvent::Expire->value);
    }

    public function testCheckExpiryValue(): void
    {
        self::assertSame('check_expiry', LoginEvent::CheckExpiry->value);
    }
}
