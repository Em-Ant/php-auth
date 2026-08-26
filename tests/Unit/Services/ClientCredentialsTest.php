<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Services;

use AuthServer\Services\ClientCredentials;
use PHPUnit\Framework\TestCase;

class ClientCredentialsTest extends TestCase
{
    public function testMergesBasicHeaderWithColonInSecret(): void
    {
        $header = 'Basic ' . base64_encode('client1:s3cr3t:with:colons');
        $result = ClientCredentials::mergeFromBasicHeader([], $header);

        self::assertSame('client1', $result['client_id']);
        self::assertSame('s3cr3t:with:colons', $result['client_secret']);
    }

    public function testMergesBasicHeaderWithNoSecret(): void
    {
        $header = 'Basic ' . base64_encode('client1:');
        $result = ClientCredentials::mergeFromBasicHeader([], $header);

        self::assertSame('client1', $result['client_id']);
        self::assertSame('', $result['client_secret']);
    }

    public function testMergesBasicHeaderWithEmptyParts(): void
    {
        $header = 'Basic ' . base64_encode('client1');
        $result = ClientCredentials::mergeFromBasicHeader([], $header);

        self::assertSame('client1', $result['client_id']);
        self::assertNull($result['client_secret']);
    }

    public function testBodyParamsWinOverHeader(): void
    {
        $body = ['client_id' => 'existing', 'client_secret' => 'existing_secret'];
        $header = 'Basic ' . base64_encode('client1:s3cr3t');
        $result = ClientCredentials::mergeFromBasicHeader($body, $header);

        self::assertSame('existing', $result['client_id']);
        self::assertSame('existing_secret', $result['client_secret']);
    }

    public function testNonBasicHeaderReturnsBodyUnchanged(): void
    {
        $body = ['client_id' => 'c1'];
        $result = ClientCredentials::mergeFromBasicHeader($body, 'Bearer token');

        self::assertSame($body, $result);
    }
}
