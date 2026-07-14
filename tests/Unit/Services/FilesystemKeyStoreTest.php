<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Services;

use AuthServer\Services\FilesystemKeyStore;
use PHPUnit\Framework\TestCase;

class FilesystemKeyStoreTest extends TestCase
{
    public function testFindKeysReturnsKeySet(): void
    {
        $store = new FilesystemKeyStore(__DIR__ . '/../../../keys');
        $keySet = $store->findKeys('33ce4036-0a36-45b9-ba74-6087d03c3b35');
        self::assertStringContainsString('BEGIN PUBLIC KEY', $keySet->publicKey);
        self::assertStringContainsString('PRIVATE KEY', $keySet->privateKey);
        self::assertStringContainsString('BEGIN CERTIFICATE', $keySet->cert);
        self::assertArrayHasKey('keys', $keySet->jwks);
    }

    public function testFindKeysWithMissingKidThrows(): void
    {
        $store = new FilesystemKeyStore(__DIR__ . '/../../../keys');
        $this->expectException(\RuntimeException::class);
        $store->findKeys('nonexistent-kid');
    }
}
