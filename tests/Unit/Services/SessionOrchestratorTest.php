<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Services;

use AuthServer\Exceptions\StorageFailed;
use AuthServer\Interfaces\SessionRepository;
use AuthServer\Models\Session;
use AuthServer\Services\SessionOrchestrator;
use PHPUnit\Framework\TestCase;

class SessionOrchestratorTest extends TestCase
{
    private SessionRepository $sessionRepo;
    private SessionOrchestrator $svc;

    protected function setUp(): void
    {
        $this->sessionRepo = $this->createMock(SessionRepository::class);
        $this->svc = new SessionOrchestrator($this->sessionRepo);
    }

    // ── ensureValidSession ────────────────────────────────────

    public function testEnsureValidSessionActiveAndValid(): void
    {
        $now = gmdate('Y-m-d H:i:s');
        $session = new Session('s-id', 'r-id', 'u-id', '0', $now, null, 'ACTIVE');
        $this->sessionRepo->method('findById')->with('s-id')->willReturn($session);

        $result = $this->svc->ensureValidSession('s-id', 86400, 1800);
        self::assertNotNull($result);
    }

    public function testEnsureValidSessionReturnsNullWhenNotFound(): void
    {
        $this->sessionRepo->method('findById')->willReturn(null);
        self::assertNull($this->svc->ensureValidSession('ghost', 86400, 1800));
    }

    public function testEnsureValidSessionReturnsNullWhenInactive(): void
    {
        $session = new Session('s-id', 'r-id', 'u-id', '0', '2020-01-01 00:00:00', null, 'EXPIRED');
        $this->sessionRepo->method('findById')->with('s-id')->willReturn($session);

        self::assertNull($this->svc->ensureValidSession('s-id', 86400, 1800));
    }

    // ── checkExpiry ───────────────────────────────────────────

    public function testCheckExpiryReturnsTrueForValidSession(): void
    {
        $now = gmdate('Y-m-d H:i:s');
        $session = new Session('s-id', 'r-id', 'u-id', '0', $now, null, 'ACTIVE');
        self::assertTrue($this->svc->checkExpiry($session, 86400, 1800));
    }

    public function testCheckExpiryReturnsFalseForExpiredSession(): void
    {
        $session = new Session('s-id', 'r-id', 'u-id', '0', '2020-01-01 00:00:00', null, 'ACTIVE');
        self::assertFalse($this->svc->checkExpiry($session, 1, 1));
    }

    // ── expire ────────────────────────────────────────────────

    public function testExpireCallsSetExpired(): void
    {
        $this->sessionRepo->expects($this->once())->method('setExpired')->with('s-id')->willReturn(true);
        $this->svc->expire('s-id');
    }

    public function testExpireThrowsOnFailure(): void
    {
        $this->sessionRepo->method('setExpired')->willReturn(false);
        $this->expectException(StorageFailed::class);
        $this->svc->expire('s-id');
    }

    // ── create ────────────────────────────────────────────────

    public function testCreateReturnsSession(): void
    {
        $session = new Session('s-id', 'r-id', 'u-id', '0', null, null, 'ACTIVE');
        $this->sessionRepo->method('create')->willReturn($session);

        $result = $this->svc->create('r-id', 'u-id');
        self::assertSame('s-id', $result->getId());
    }

    public function testCreateThrowsOnNull(): void
    {
        $this->sessionRepo->method('create')->willReturn(null);
        $this->expectException(StorageFailed::class);
        $this->svc->create('r-id', 'u-id');
    }

    // ── refresh ───────────────────────────────────────────────

    public function testRefreshCallsRepo(): void
    {
        $this->sessionRepo->expects($this->once())->method('refresh')->with('s-id')->willReturn(true);
        $this->svc->refresh('s-id');
    }

    public function testRefreshThrowsOnFailure(): void
    {
        $this->sessionRepo->method('refresh')->willReturn(false);
        $this->expectException(StorageFailed::class);
        $this->svc->refresh('s-id');
    }
}
