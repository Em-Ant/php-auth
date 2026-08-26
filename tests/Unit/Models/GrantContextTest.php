<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Models;

use AuthServer\Models\GrantContext;
use AuthServer\Models\Login;
use AuthServer\Models\Session;
use PHPUnit\Framework\TestCase;

class GrantContextTest extends TestCase
{
    public function testFromSessionFallsBackToTimeWhenAuthenticatedAtIsNull(): void
    {
        $session = new Session(
            id: 'sess-1',
            realm_id: 'realm-1',
            user_id: 'user-1',
            acr: '0',
        );

        $login = new Login(
            id: 'login-1',
            client_id: 'client-1',
            state: 'st',
            nonce: 'nc',
            scope: 'openid',
            redirect_uri: 'https://example.com',
            response_mode: 'query',
            created_at: null,
            session_id: 'sess-1',
            authenticated_at: null,
            code: null,
            code_challenge: null,
            csrf_token: null,
            updated_at: null,
            refresh_token: null,
            status: 'PENDING',
        );

        $before = time();
        $context = GrantContext::fromSession($session, $login);
        $after = time();

        self::assertGreaterThanOrEqual($before, $context->authTime);
        self::assertLessThanOrEqual($after, $context->authTime);
    }

    public function testFromSessionUsesAuthenticatedAtWhenPresent(): void
    {
        $session = new Session(
            id: 'sess-2',
            realm_id: 'realm-1',
            user_id: 'user-1',
            acr: '0',
        );

        $login = new Login(
            id: 'login-2',
            client_id: 'client-1',
            state: 'st',
            nonce: 'nc',
            scope: 'openid',
            redirect_uri: 'https://example.com',
            response_mode: 'query',
            created_at: null,
            session_id: 'sess-2',
            authenticated_at: '2025-06-15 12:00:00',
            code: null,
            code_challenge: null,
            csrf_token: null,
            updated_at: null,
            refresh_token: null,
            status: 'ACTIVE',
        );

        $context = GrantContext::fromSession($session, $login);

        self::assertSame(1749988800, $context->authTime);
    }
}
