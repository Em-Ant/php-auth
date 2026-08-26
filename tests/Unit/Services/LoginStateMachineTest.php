<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Services;

use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\LoginRepository as ILoginRepo;
use AuthServer\Models\Login;
use AuthServer\Models\LoginEvent;
use AuthServer\Models\LoginStatus;
use AuthServer\Models\Realm;
use AuthServer\Services\LoginStateMachine;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

class LoginStateMachineTest extends TestCase
{
    private LoginStateMachine $machine;
    private ILoginRepo&\PHPUnit\Framework\MockObject\MockObject $loginRepo;
    private LoggerInterface&\PHPUnit\Framework\MockObject\MockObject $logger;
    private Realm $realm;

    protected function setUp(): void
    {
        $this->loginRepo = $this->createMock(ILoginRepo::class);
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->machine = new LoginStateMachine($this->loginRepo, $this->logger);
        $this->realm = new Realm(
            'r-id', 'test', 'k-id',
            1800, 300, 300, 300, 86400, 1800,
            'openid', '2025-01-01 00:00:00',
        );
    }

    private function makeLogin(LoginStatus $status, ?string $createdAt = null, ?string $authenticatedAt = null, ?string $updatedAt = null): Login
    {
        return new Login(
            id: 'login-1',
            client_id: 'client-1',
            state: 'state-1',
            nonce: 'nonce-1',
            scope: 'openid',
            redirect_uri: 'https://example.com/cb',
            response_mode: 'query',
            created_at: $createdAt ?? date('Y-m-d H:i:s'),
            session_id: null,
            authenticated_at: $authenticatedAt,
            code: null,
            code_challenge: null,
            csrf_token: 'csrf-1',
            updated_at: $updatedAt,
            refresh_token: null,
            status: $status->value,
        );
    }

    // ── Authenticate ──────────────────────────────────────────

    public function testAuthenticateTransitionsPendingToAuthenticated(): void
    {
        $login = $this->makeLogin(LoginStatus::Pending);

        $this->loginRepo->expects($this->once())->method('setAuthenticated')
            ->with($login->getId(), 'session-1', 'code-abc')->willReturn(true);
        $this->logger->expects($this->once())->method('info');

        $result = $this->machine->transition($login, LoginEvent::Authenticate, $this->realm, [
            'session_id' => 'session-1',
            'code' => 'code-abc',
        ]);

        self::assertSame(LoginStatus::Authenticated, $result->getStatus());
        self::assertSame('session-1', $result->getSessionId());
        self::assertSame('code-abc', $result->getCode());
    }

    public function testAuthenticateFromWrongStatusThrows(): void
    {
        $login = $this->makeLogin(LoginStatus::Active);
        $this->loginRepo->expects($this->never())->method('setAuthenticated');
        $this->expectException(ValidationFailed::class);

        $this->machine->transition($login, LoginEvent::Authenticate, $this->realm, [
            'session_id' => 's1', 'code' => 'c1',
        ]);
    }

    public function testAuthenticateExpiredLoginThrows(): void
    {
        $login = $this->makeLogin(LoginStatus::Pending, createdAt: '2000-01-01 00:00:00');
        $this->loginRepo->expects($this->never())->method('setAuthenticated');
        $this->expectException(ValidationFailed::class);
        $this->expectExceptionMessage('expired');

        $this->machine->transition($login, LoginEvent::Authenticate, $this->realm, [
            'session_id' => 's1', 'code' => 'c1',
        ]);

        self::assertSame(LoginStatus::Expired, $login->getStatus());
    }

    // ── Activate ──────────────────────────────────────────────

    public function testActivateTransitionsAuthenticatedToActive(): void
    {
        $login = $this->makeLogin(LoginStatus::Authenticated, authenticatedAt: date('Y-m-d H:i:s'));

        $this->loginRepo->expects($this->once())->method('setActive')
            ->with($login->getId(), 'rt-1')->willReturn(true);
        $this->logger->expects($this->once())->method('info');

        $result = $this->machine->transition($login, LoginEvent::Activate, $this->realm, [
            'refresh_token' => 'rt-1',
        ]);

        self::assertSame(LoginStatus::Active, $result->getStatus());
        self::assertSame('rt-1', $result->getRefreshToken());
    }

    public function testActivateFromWrongStatusThrows(): void
    {
        $login = $this->makeLogin(LoginStatus::Pending);
        $this->loginRepo->expects($this->never())->method('setActive');
        $this->expectException(ValidationFailed::class);

        $this->machine->transition($login, LoginEvent::Activate, $this->realm, [
            'refresh_token' => 'rt-1',
        ]);
    }

    // ── Refresh ───────────────────────────────────────────────

    public function testRefreshTransitionsActiveLogin(): void
    {
        $login = $this->makeLogin(LoginStatus::Active, updatedAt: date('Y-m-d H:i:s'));

        $this->loginRepo->expects($this->once())->method('refresh')
            ->with($login->getId(), 'rt-2')->willReturn(true);
        $this->logger->expects($this->once())->method('info');

        $result = $this->machine->transition($login, LoginEvent::Refresh, $this->realm, [
            'refresh_token' => 'rt-2',
        ]);

        self::assertSame(LoginStatus::Active, $result->getStatus());
        self::assertSame('rt-2', $result->getRefreshToken());
    }

    public function testRefreshFromWrongStatusThrows(): void
    {
        $login = $this->makeLogin(LoginStatus::Pending);
        $this->loginRepo->expects($this->never())->method('refresh');
        $this->expectException(ValidationFailed::class);

        $this->machine->transition($login, LoginEvent::Refresh, $this->realm, [
            'refresh_token' => 'rt-2',
        ]);
    }

    // ── Expire ────────────────────────────────────────────────

    public function testExpireNonExpiredLogin(): void
    {
        $login = $this->makeLogin(LoginStatus::Active, updatedAt: date('Y-m-d H:i:s'));

        $this->loginRepo->expects($this->once())->method('setExpired')
            ->with($login->getId())->willReturn(true);
        $this->logger->expects($this->once())->method('info');

        $result = $this->machine->transition($login, LoginEvent::Expire, $this->realm);

        self::assertSame(LoginStatus::Expired, $result->getStatus());
    }

    public function testExpireAlreadyExpiredIsNoOp(): void
    {
        $login = $this->makeLogin(LoginStatus::Expired);

        $this->loginRepo->expects($this->never())->method('setExpired');

        $result = $this->machine->transition($login, LoginEvent::Expire, $this->realm);

        self::assertSame($login, $result);
    }

    // ── CheckExpiry ───────────────────────────────────────────

    public function testCheckExpiryUnderTtlReturnsSame(): void
    {
        $login = $this->makeLogin(LoginStatus::Pending, createdAt: date('Y-m-d H:i:s'));

        $result = $this->machine->transition($login, LoginEvent::CheckExpiry, $this->realm);

        self::assertSame($login, $result);
        self::assertSame(LoginStatus::Pending, $result->getStatus());
    }

    public function testCheckExpiryPastTtlReturnsExpired(): void
    {
        $login = $this->makeLogin(LoginStatus::Pending, createdAt: '2000-01-01 00:00:00');

        $this->loginRepo->expects($this->once())->method('setExpired')
            ->with($login->getId())->willReturn(true);

        $result = $this->machine->transition($login, LoginEvent::CheckExpiry, $this->realm);

        self::assertSame(LoginStatus::Expired, $result->getStatus());
    }

    public function testCheckExpiryAlreadyExpiredReturnsSame(): void
    {
        $login = $this->makeLogin(LoginStatus::Expired);

        $result = $this->machine->transition($login, LoginEvent::CheckExpiry, $this->realm);

        self::assertSame($login, $result);
    }

    // ── Repository failure paths ──────────────────────────────

    public function testAuthenticateRepoFailureThrows(): void
    {
        $login = $this->makeLogin(LoginStatus::Pending);
        $this->loginRepo->method('setAuthenticated')->willReturn(false);
        $this->expectException(\RuntimeException::class);

        $this->machine->transition($login, LoginEvent::Authenticate, $this->realm, [
            'session_id' => 's1', 'code' => 'c1',
        ]);
    }

    public function testActivateRepoFailureThrows(): void
    {
        $login = $this->makeLogin(LoginStatus::Authenticated, authenticatedAt: date('Y-m-d H:i:s'));
        $this->loginRepo->method('setActive')->willReturn(false);
        $this->expectException(\RuntimeException::class);

        $this->machine->transition($login, LoginEvent::Activate, $this->realm, [
            'refresh_token' => 'rt-1',
        ]);
    }

    public function testRefreshRepoFailureThrows(): void
    {
        $login = $this->makeLogin(LoginStatus::Active, updatedAt: date('Y-m-d H:i:s'));
        $this->loginRepo->method('refresh')->willReturn(false);
        $this->expectException(\RuntimeException::class);

        $this->machine->transition($login, LoginEvent::Refresh, $this->realm, [
            'refresh_token' => 'rt-2',
        ]);
    }

    public function testExpireRepoFailureThrows(): void
    {
        $login = $this->makeLogin(LoginStatus::Active, updatedAt: date('Y-m-d H:i:s'));
        $this->loginRepo->method('setExpired')->willReturn(false);
        $this->expectException(\RuntimeException::class);

        $this->machine->transition($login, LoginEvent::Expire, $this->realm);
    }
}
