<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Services;

use AuthServer\Exceptions\OAuth2Error;
use AuthServer\Models\Login;
use AuthServer\Models\LoginStatus;
use AuthServer\Models\Realm;
use AuthServer\Services\ActiveSessionResolver;
use AuthServer\Services\ClientAuthenticator;
use AuthServer\Services\LoginStateMachine;
use AuthServer\Services\OfflineSessionService;
use AuthServer\Services\TokenGrantService;
use AuthServer\Services\TokenService;
use AuthServer\Services\TokenValidator;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

class TokenGrantServiceTest extends TestCase
{
    private Realm $realm;

    protected function setUp(): void
    {
        $this->realm = new Realm(
            'r-id', 'test', 'k-id',
            1800, 300, 300, 300, 86400, 1800,
            'openid', '2025-01-01 00:00:00',
        );
    }

    public function testGetTokensByRefreshTokenThrowsWhenLoginExpiredByCheckExpiry(): void
    {
        $login = new Login(
            id: 'login-1',
            client_id: 'client-1',
            state: 'state-1',
            nonce: 'nonce-1',
            scope: 'openid',
            redirect_uri: 'https://example.com/cb',
            response_mode: 'query',
            created_at: '2000-01-01 00:00:00',
            session_id: 'session-1',
            authenticated_at: '2000-01-01 00:00:00',
            code: null,
            code_challenge: null,
            csrf_token: 'csrf-1',
            updated_at: '2000-01-01 00:00:00',
            refresh_token: 'refresh-tok',
            status: 'ACTIVE',
        );

        $expiredLogin = clone $login;
        $expiredLogin->setStatus(LoginStatus::Expired);

        $tokenValidator = $this->createMock(TokenValidator::class);
        $tokenValidator->method('decodeClaimsOnly')->willReturn(['typ' => 'Refresh']);

        $loginStateMachine = $this->createMock(LoginStateMachine::class);
        $loginStateMachine->method('findByRefreshToken')->willReturn($login);
        $loginStateMachine->method('transition')->with(
            $login,
            \AuthServer\Models\LoginEvent::CheckExpiry,
            $this->realm,
        )->willReturn($expiredLogin);

        $clientAuth = $this->createMock(ClientAuthenticator::class);
        $clientAuth->method('authenticate')->willReturn(
            new \AuthServer\Models\Client('client-1', 'app', 'r-id', null, 'https://example.com', false, date('Y-m-d H:i:s')),
        );

        $logger = $this->createMock(LoggerInterface::class);

        $svc = new TokenGrantService(
            $this->createMock(ActiveSessionResolver::class),
            $loginStateMachine,
            $clientAuth,
            $this->createMock(TokenService::class),
            $tokenValidator,
            $this->createMock(OfflineSessionService::class),
            $logger,
        );

        $this->expectException(OAuth2Error::class);
        $this->expectExceptionMessage('expired');

        $svc->getTokens(
            ['client_id' => 'client-1', 'grant_type' => 'refresh_token', 'refresh_token' => 'refresh-tok'],
            $this->realm,
        );
    }
}
