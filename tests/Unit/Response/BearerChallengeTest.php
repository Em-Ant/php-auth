<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Response;

use AuthServer\Response\BearerChallenge;
use PHPUnit\Framework\TestCase;

class BearerChallengeTest extends TestCase
{
    public function testCreateBuildsRfc6750Challenge(): void
    {
        self::assertSame(
            'Bearer realm="test", error="invalid_token", error_description="token expired"',
            BearerChallenge::create('test', 'token expired')
        );
    }

    public function testRemovesQuotesFromRealmAndDescription(): void
    {
        self::assertSame(
            'Bearer realm="weirdrealm", error="invalid_token", error_description="bad token value"',
            BearerChallenge::create('weird"realm', 'bad "token" value')
        );
    }

    public function testRemovesCrLfToPreventHeaderSplitting(): void
    {
        self::assertSame(
            'Bearer realm="xX-Evil: 1", error="invalid_token", error_description="no newlinesInjected: 1"',
            BearerChallenge::create("x\r\nX-Evil: 1", "no newlines\r\n\r\nInjected: 1")
        );
    }
}
