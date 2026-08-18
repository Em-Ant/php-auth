<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration\Repositories;

use AuthServer\Exceptions\StorageFailed;
use AuthServer\Models\Login;
use AuthServer\Models\LoginStatus;
use AuthServer\Repositories\LoginRepository;
use AuthServer\Repositories\SessionRepository;
use AuthServer\Tests\Integration\RepositoryTestCase;
use AuthServer\Tests\Support\FailingPdo;

class LoginRepositoryTest extends RepositoryTestCase
{
    private const TEST_REALM_ID = 'c03aa58c-2888-4f40-821c-4aadf5c58f6f';
    private const OTHER_REALM_ID = '84be68b8-7936-4422-bb4d-b741d2292a9f';

    private LoginRepository $repo;
    private SessionRepository $sessionRepo;

    protected function setUp(): void
    {
        $this->repo = new LoginRepository(self::$pdo);
        $this->sessionRepo = new SessionRepository(self::$pdo);
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

    private function createAuthenticatedLogin(string $code): Login
    {
        $login = $this->createPendingLogin();
        $this->repo->setAuthenticated($login->getId(), $this->createSession(), $code);
        $updated = $this->repo->findById($login->getId());
        self::assertNotNull($updated);
        return $updated;
    }

    private function createPendingLogin(): Login
    {
        $login = $this->repo->createPending(
            client_id: 'a540c566-dfbf-430a-9941-fb8531c022d4',
            state: 's', nonce: 'n', scope: 'openid',
            redirect_uri: 'http://localhost:5173/cb',
            response_mode: 'query',
            code_challenge: null, csrf_token: 'csrf',
        );
        self::assertNotNull($login);
        return $login;
    }

    private function createActiveLogin(string $code, string $refreshToken): Login
    {
        $login = $this->createPendingLogin();
        $this->repo->setAuthenticated($login->getId(), $this->createSession(), $code);
        $this->repo->setActive($login->getId(), $refreshToken);
        return $login;
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
        $login = $this->createAuthenticatedLogin('code-abc-123');
        self::assertSame(LoginStatus::Authenticated, $login->getStatus());

        $found = $this->repo->findByCode('code-abc-123', self::TEST_REALM_ID);
        self::assertNotNull($found);
        self::assertSame($login->getId(), $found->getId());
    }

    public function testFindByCodeReturnsNullForMissing(): void
    {
        self::assertNull($this->repo->findByCode('bogus', self::TEST_REALM_ID));
    }

    public function testFindByCodeScopedToRealm(): void
    {
        $login = $this->createAuthenticatedLogin('code-realm-scoped');

        self::assertSame($login->getId(), $this->repo->findByCode('code-realm-scoped', self::TEST_REALM_ID)?->getId());
        self::assertNull($this->repo->findByCode('code-realm-scoped', self::OTHER_REALM_ID));
    }

    public function testSetAuthenticated(): void
    {
        $login = $this->createPendingLogin();

        $ok = $this->repo->setAuthenticated($login->getId(), $this->createSession(), 'code-xyz');
        self::assertTrue($ok);

        $updated = $this->repo->findById($login->getId());
        self::assertSame(LoginStatus::Authenticated, $updated->getStatus());
        self::assertSame('code-xyz', $updated->getCode());
    }

    public function testSetActive(): void
    {
        $login = $this->createAuthenticatedLogin('code-act');

        $ok = $this->repo->setActive($login->getId(), 'refresh-token-1');
        self::assertTrue($ok);

        $updated = $this->repo->findById($login->getId());
        self::assertSame(LoginStatus::Active, $updated->getStatus());
        self::assertSame('refresh-token-1', $updated->getRefreshToken());
    }

    public function testRefresh(): void
    {
        $login = $this->createActiveLogin('code-ref', 'old-refresh-token');

        $ok = $this->repo->refresh($login->getId(), 'new-refresh-token');
        self::assertTrue($ok);

        $updated = $this->repo->findById($login->getId());
        self::assertSame(LoginStatus::Active, $updated->getStatus());
        self::assertSame('new-refresh-token', $updated->getRefreshToken());
        self::assertNotNull($updated->getUpdatedAt());
    }

    public function testSetExpired(): void
    {
        $login = $this->createPendingLogin();

        $ok = $this->repo->setExpired($login->getId());
        self::assertTrue($ok);

        $updated = $this->repo->findById($login->getId());
        self::assertSame(LoginStatus::Expired, $updated->getStatus());
    }

    public function testFindByRefreshToken(): void
    {
        $login = $this->createActiveLogin('code-rt', 'rt-findme');

        $found = $this->repo->findByRefreshToken('rt-findme', self::TEST_REALM_ID);
        self::assertNotNull($found);
        self::assertSame($login->getId(), $found->getId());
    }

    public function testFindByRefreshTokenReturnsNullForMissing(): void
    {
        self::assertNull($this->repo->findByRefreshToken('bogus', self::TEST_REALM_ID));
    }

    public function testFindByRefreshTokenScopedToRealm(): void
    {
        $login = $this->createActiveLogin('code-rt-realm', 'rt-realm-scoped');

        self::assertSame($login->getId(), $this->repo->findByRefreshToken('rt-realm-scoped', self::TEST_REALM_ID)?->getId());
        self::assertNull($this->repo->findByRefreshToken('rt-realm-scoped', self::OTHER_REALM_ID));
    }

    public function testStorageFailureOnFindByIdThrows(): void
    {
        $repo = new LoginRepository(new FailingPdo());

        $this->expectException(StorageFailed::class);
        $repo->findById('existing-id');
    }
}
