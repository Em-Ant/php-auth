<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration\Repositories;

use AuthServer\Models\LoginStatus;
use AuthServer\Repositories\LoginRepository;
use AuthServer\Repositories\SessionRepository;
use AuthServer\Tests\Integration\RepositoryTestCase;
use Psr\Log\LoggerInterface;

class LoginRepositoryTest extends RepositoryTestCase
{
    private LoginRepository $repo;
    private SessionRepository $sessionRepo;

    protected function setUp(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $this->repo = new LoginRepository(self::$pdo, $logger);
        $this->sessionRepo = new SessionRepository(self::$pdo, $logger);
    }

    private function createSession(): string
    {
        $session = $this->sessionRepo->create(
            '84be68b8-7936-4422-bb4d-b741d2292a9f',
            '586d7bb3-d386-4b57-9e99-b2a460f20b47',
            '0',
        );
        self::assertNotNull($session);
        return $session->getId();
    }

    public function testCreatePending(): void
    {
        $login = $this->repo->createPending(
            client_id: 'a540c566-dfbf-430a-9941-fb8531c022d4',
            state: 'state-1',
            nonce: 'nonce-1',
            scope: 'openid',
            redirect_uri: 'http://localhost:5173/cb',
            response_mode: 'query',
            code_challenge: null,
            csrf_token: 'csrf-1',
        );
        self::assertNotNull($login);
        self::assertSame(LoginStatus::Pending, $login->getStatus());
        self::assertSame('state-1', $login->getState());
        self::assertSame('csrf-1', $login->getCsrfToken());
    }

    public function testFindByIdReturnsNullForMissing(): void
    {
        self::assertNull($this->repo->findById('nonexistent'));
    }

    public function testCreateAuthenticatedAndFindByCode(): void
    {
        $sessionId = $this->createSession();

        $login = $this->repo->createAuthenticated(
            client_id: 'a540c566-dfbf-430a-9941-fb8531c022d4',
            session_id: $sessionId,
            state: 'state-2',
            nonce: 'nonce-2',
            scope: 'openid',
            redirect_uri: 'http://localhost:5173/cb',
            response_mode: 'query',
            code: 'code-abc-123',
            code_challenge: null,
        );
        self::assertNotNull($login);
        self::assertSame(LoginStatus::Authenticated, $login->getStatus());

        $found = $this->repo->findByCode('code-abc-123');
        self::assertNotNull($found);
        self::assertSame($login->getId(), $found->getId());
    }

    public function testFindByCodeReturnsNullForMissing(): void
    {
        self::assertNull($this->repo->findByCode('bogus'));
    }

    public function testSetAuthenticated(): void
    {
        $login = $this->repo->createPending(
            client_id: 'a540c566-dfbf-430a-9941-fb8531c022d4',
            state: 's', nonce: 'n', scope: 'openid',
            redirect_uri: 'http://localhost:5173/cb',
            response_mode: 'query',
            code_challenge: null, csrf_token: 'csrf',
        );

        $ok = $this->repo->setAuthenticated($login->getId(), $this->createSession(), 'code-xyz');
        self::assertTrue($ok);

        $updated = $this->repo->findById($login->getId());
        self::assertSame(LoginStatus::Authenticated, $updated->getStatus());
        self::assertSame('code-xyz', $updated->getCode());
    }

    public function testSetActive(): void
    {
        $sessionId = $this->createSession();

        $login = $this->repo->createAuthenticated(
            client_id: 'a540c566-dfbf-430a-9941-fb8531c022d4',
            session_id: $sessionId, state: 's', nonce: 'n',
            scope: 'openid', redirect_uri: 'http://localhost:5173/cb',
            response_mode: 'query', code: 'code-act', code_challenge: null,
        );
        self::assertNotNull($login);

        $ok = $this->repo->setActive($login->getId(), 'refresh-token-1');
        self::assertTrue($ok);

        $updated = $this->repo->findById($login->getId());
        self::assertSame(LoginStatus::Active, $updated->getStatus());
        self::assertSame('refresh-token-1', $updated->getRefreshToken());
    }

    public function testRefresh(): void
    {
        $login = $this->repo->createPending(
            client_id: 'a540c566-dfbf-430a-9941-fb8531c022d4',
            state: 's', nonce: 'n', scope: 'openid',
            redirect_uri: 'http://localhost:5173/cb',
            response_mode: 'query',
            code_challenge: null, csrf_token: 'csrf',
        );
        $this->repo->setAuthenticated($login->getId(), $this->createSession(), 'code-ref');
        $this->repo->setActive($login->getId(), 'old-refresh-token');

        $ok = $this->repo->refresh($login->getId(), 'new-refresh-token');
        self::assertTrue($ok);

        $updated = $this->repo->findById($login->getId());
        self::assertSame(LoginStatus::Active, $updated->getStatus());
        self::assertSame('new-refresh-token', $updated->getRefreshToken());
        self::assertNotNull($updated->getUpdatedAt());
    }

    public function testSetExpired(): void
    {
        $login = $this->repo->createPending(
            client_id: 'a540c566-dfbf-430a-9941-fb8531c022d4',
            state: 's', nonce: 'n', scope: 'openid',
            redirect_uri: 'http://localhost:5173/cb',
            response_mode: 'query',
            code_challenge: null, csrf_token: 'csrf',
        );

        $ok = $this->repo->setExpired($login->getId());
        self::assertTrue($ok);

        $updated = $this->repo->findById($login->getId());
        self::assertSame(LoginStatus::Expired, $updated->getStatus());
    }

    public function testFindByRefreshToken(): void
    {
        $login = $this->repo->createPending(
            client_id: 'a540c566-dfbf-430a-9941-fb8531c022d4',
            state: 's', nonce: 'n', scope: 'openid',
            redirect_uri: 'http://localhost:5173/cb',
            response_mode: 'query',
            code_challenge: null, csrf_token: 'csrf',
        );
        $this->repo->setAuthenticated($login->getId(), $this->createSession(), 'code-rt');
        $this->repo->setActive($login->getId(), 'rt-findme');

        $found = $this->repo->findByrefreshToken('rt-findme');
        self::assertNotNull($found);
        self::assertSame($login->getId(), $found->getId());
    }

    public function testFindByRefreshTokenReturnsNullForMissing(): void
    {
        self::assertNull($this->repo->findByrefreshToken('bogus'));
    }
}
