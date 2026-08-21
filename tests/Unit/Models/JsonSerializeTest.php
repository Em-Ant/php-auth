<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Models;

use AuthServer\Models\Client;
use AuthServer\Models\Login;
use AuthServer\Models\OfflineSession;
use AuthServer\Models\Realm;
use AuthServer\Models\Session;
use AuthServer\Models\User;
use PHPUnit\Framework\TestCase;

class JsonSerializeTest extends TestCase
{
    private const NOW = '2026-08-21 10:00:00';

    public function testUserSerializationExcludesPassword(): void
    {
        $user = new User(
            'u1',
            'r1',
            'Alice',
            'alice@example.com',
            '$argon2id$hash',
            ['admin', 'user'],
            self::NOW
        );

        $data = $user->jsonSerialize();

        self::assertArrayNotHasKey('password', $data);
        self::assertSame('u1', $data['id']);
        self::assertSame('r1', $data['realm_id']);
        self::assertSame('Alice', $data['name']);
        self::assertSame('alice@example.com', $data['email']);
        self::assertSame(['admin', 'user'], $data['realm_roles']);
        self::assertSame([], $data['client_roles']);
        self::assertTrue($data['valid']);
        self::assertSame(self::NOW, $data['created_at']);
    }

    public function testLoginSerializationExcludesCodeAndTokens(): void
    {
        $login = new Login(
            'l1',
            'c1',
            'state',
            'nonce',
            'openid',
            'https://rp/callback',
            'query',
            self::NOW,
            's1',
            self::NOW,
            'secret-code',
            'code-challenge',
            'csrf-token',
            self::NOW,
            'refresh-token',
            'AUTHENTICATED'
        );

        $data = $login->jsonSerialize();

        self::assertArrayNotHasKey('code', $data);
        self::assertArrayNotHasKey('code_challenge', $data);
        self::assertArrayNotHasKey('csrf_token', $data);
        self::assertArrayNotHasKey('refresh_token', $data);
        self::assertSame('l1', $data['id']);
        self::assertSame('s1', $data['session_id']);
        self::assertSame('c1', $data['client_id']);
        self::assertSame('AUTHENTICATED', $data['status']);
        self::assertSame(self::NOW, $data['authenticated_at']);
    }

    public function testClientSerializationExcludesClientSecret(): void
    {
        $client = new Client(
            'c1',
            'app',
            'r1',
            'secret-hash',
            'https://app',
            true,
            self::NOW,
            'openid profile'
        );

        $data = $client->jsonSerialize();

        self::assertArrayNotHasKey('client_secret', $data);
        self::assertSame('c1', $data['id']);
        self::assertSame('app', $data['name']);
        self::assertSame('openid profile', $data['scope']);
        self::assertTrue($data['require_auth']);
    }

    public function testOfflineSessionSerializationExcludesRefreshToken(): void
    {
        $offlineSession = new OfflineSession(
            'o1',
            'r1',
            'u1',
            'c1',
            'openid offline_access',
            self::NOW,
            '1',
            'nonce',
            self::NOW,
            self::NOW,
            'refresh-token'
        );

        $data = $offlineSession->jsonSerialize();

        self::assertArrayNotHasKey('refresh_token', $data);
        self::assertArrayNotHasKey('nonce', $data);
        self::assertSame('o1', $data['id']);
        self::assertSame('ACTIVE', $data['status']);
        self::assertSame(self::NOW, $data['updated_at']);
    }

    public function testSessionSerializationHasNoSensitiveFields(): void
    {
        $session = new Session('s1', 'r1', 'u1', '1', self::NOW, self::NOW);

        $data = $session->jsonSerialize();

        self::assertSame('s1', $data['id']);
        self::assertSame('u1', $data['user_id']);
        self::assertSame('ACTIVE', $data['status']);
        self::assertSame(self::NOW, $data['updated_at']);
    }

    public function testRealmSerializationHasNoSensitiveFields(): void
    {
        $realm = new Realm(
            'r1',
            'web',
            'keys-1',
            300,
            60,
            120,
            600,
            3600,
            1800,
            'openid profile',
            self::NOW
        );

        $data = $realm->jsonSerialize();

        self::assertSame('r1', $data['id']);
        self::assertSame('web', $data['name']);
        self::assertSame(['openid', 'profile'], $data['scope']);
        self::assertSame(2592000, $data['offline_refresh_token_expires_in']);
    }
}
