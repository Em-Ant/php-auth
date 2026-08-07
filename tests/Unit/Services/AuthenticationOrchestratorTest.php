<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Services;

use AuthServer\Exceptions\AuthenticationFailed;
use AuthServer\Exceptions\StorageFailed;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\ClientRepository as IClientRepo;
use AuthServer\Interfaces\LoginRepository as ILoginRepo;
use AuthServer\Interfaces\UserRepository as IUserRepo;
use AuthServer\Models\Client;
use AuthServer\Models\Login;
use AuthServer\Models\Realm;
use AuthServer\Models\Session;
use AuthServer\Models\User;
use AuthServer\Services\AuthenticationOrchestrator;
use AuthServer\Services\LoginStateMachine;
use AuthServer\Services\ScopeResolver;
use AuthServer\Services\SecretsService;
use AuthServer\Services\SessionOrchestrator;
use AuthServer\Services\TokenService;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

class AuthenticationOrchestratorTest extends TestCase
{
    private IClientRepo $clientRepo;
    private IUserRepo $userRepo;
    private ILoginRepo $loginRepo;
    private LoginStateMachine $stateMachine;
    private SecretsService $secretsService;
    private TokenService $tokenService;
    private LoggerInterface $logger;
    private SessionOrchestrator $sessionOrch;
    private AuthenticationOrchestrator $svc;
    private Realm $realm;
    private Client $client;
    private Session $session;
    private User $user;

    protected function setUp(): void
    {
        $this->clientRepo = $this->createMock(IClientRepo::class);
        $this->userRepo = $this->createMock(IUserRepo::class);
        $this->loginRepo = $this->createMock(ILoginRepo::class);
        $this->stateMachine = $this->createMock(LoginStateMachine::class);
        $this->secretsService = $this->createMock(SecretsService::class);
        $this->tokenService = $this->createMock(TokenService::class);
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->sessionOrch = $this->createMock(SessionOrchestrator::class);

        $this->svc = new AuthenticationOrchestrator(
            $this->sessionOrch,
            $this->clientRepo,
            $this->userRepo,
            $this->loginRepo,
            $this->stateMachine,
            $this->secretsService,
            $this->tokenService,
            new ScopeResolver(new NullLogger()),
            $this->logger,
        );

        $this->realm = new Realm(
            'r-id', 'test', 'k-id',
            1800, 300, 300, 300, 86400, 1800,
            'openid profile', '2025-01-01 00:00:00',
        );

        $this->client = new Client(
            'c-id', 'my-app', 'r-id', null, 'http://example.com', false, '2025-01-01 00:00:00',
        );

        $now = gmdate('Y-m-d H:i:s');
        $this->session = new Session('s-id', 'r-id', 'u-id', '0', $now, null, 'ACTIVE');

        $this->user = new User(
            'u-id', 'r-id', 'emant', 'test@example.com', 'hashed', 'basic admin', '2025-01-01 00:00:00',
        );
    }

    // ── validateRequiredLoginScope ────────────────────────────

    public function testValidateRequiredLoginScopePasses(): void
    {
        $this->clientRepo->expects($this->once())
            ->method('findByName')
            ->with('my-app')
            ->willReturn($this->client);
        $this->svc->validateRequiredLoginScope($this->realm, 'my-app', 'openid');
    }

    public function testValidateRequiredLoginScopeMissingOpenidThrows(): void
    {
        $this->clientRepo->method('findByName')->with('my-app')->willReturn($this->client);
        $this->expectException(ValidationFailed::class);
        $this->svc->validateRequiredLoginScope($this->realm, 'my-app', 'profile');
    }

    public function testValidateRequiredLoginScopeClientNotFoundThrows(): void
    {
        $this->clientRepo->method('findByName')->with('ghost')->willReturn(null);
        $this->expectException(ValidationFailed::class);
        $this->svc->validateRequiredLoginScope($this->realm, 'ghost', 'openid');
    }

    // ── initializeLogin ───────────────────────────────────────

    public function testInitializeLoginHappyPath(): void
    {
        $query = [
            'client_id' => 'my-app',
            'redirect_uri' => 'http://example.com',
            'response_type' => 'code',
            'response_mode' => 'query',
            'scope' => 'openid',
            'state' => 'st',
            'nonce' => 'nc',
            'code_challenge' => null,
        ];

        $this->clientRepo->method('findByName')->with('my-app')->willReturn($this->client);
        $this->secretsService->method('generateCode')->willReturn('csrf-abc');
        $this->loginRepo->method('createPending')->willReturn(
            new Login(
                id: 'login-1', client_id: 'c-id', state: 'st', nonce: 'nc',
                scope: 'openid', redirect_uri: 'http://example.com', response_mode: 'query',
                created_at: date('Y-m-d H:i:s'), session_id: null,
                authenticated_at: null, code: null, code_challenge: null,
                csrf_token: 'csrf-abc', updated_at: null, refresh_token: null,
                status: 'PENDING',
            ),
        );

        $result = $this->svc->initializeLogin('r-id', $query);
        self::assertSame('login-1', $result['login_id']);
        self::assertSame('csrf-abc', $result['csrf_token']);
    }

    public function testInitializeLoginNullFromRepoThrows(): void
    {
        $query = [
            'client_id' => 'my-app', 'redirect_uri' => 'http://example.com',
            'response_type' => 'code', 'response_mode' => 'query',
            'scope' => 'openid', 'state' => 'st', 'nonce' => 'nc',
            'code_challenge' => null,
        ];
        $this->clientRepo->method('findByName')->willReturn($this->client);
        $this->loginRepo->method('createPending')->willReturn(null);

        $this->expectException(StorageFailed::class);
        $this->svc->initializeLogin('r-id', $query);
    }

    // ── validateCsrfToken ─────────────────────────────────────

    public function testValidateCsrfTokenMatching(): void
    {
        $login = $this->createMock(Login::class);
        $login->method('getCsrfToken')->willReturn('csrf-abc');
        $this->loginRepo->method('findById')->with('login-1')->willReturn($login);

        $this->svc->validateCsrfToken('login-1', 'csrf-abc');
        self::assertTrue(true);
    }

    public function testValidateCsrfTokenMismatchThrows(): void
    {
        $login = $this->createMock(Login::class);
        $login->method('getCsrfToken')->willReturn('csrf-abc');
        $this->loginRepo->method('findById')->willReturn($login);

        $this->expectException(ValidationFailed::class);
        $this->svc->validateCsrfToken('login-1', 'wrong-csrf');
    }

    // ── createAuthorizedLogin ──────────────────────────────────

    public function testCreateAuthorizedLoginHappyPath(): void
    {
        $query = [
            'client_id' => 'my-app', 'redirect_uri' => 'http://example.com',
            'response_type' => 'code', 'response_mode' => 'query',
            'scope' => 'openid', 'state' => 'st', 'nonce' => 'nc',
        ];

        $this->clientRepo->method('findByName')->willReturn($this->client);
        $this->userRepo->method('findById')->with('u-id')->willReturn($this->user);
        $this->secretsService->method('generateCode')->willReturn('code-abc');
        $this->loginRepo->method('createAuthenticated')->willReturn(
            new Login(
                id: 'login-2', client_id: 'c-id', state: 'st', nonce: 'nc',
                scope: 'openid', redirect_uri: 'http://example.com', response_mode: 'query',
                created_at: date('Y-m-d H:i:s'), session_id: 's-id',
                authenticated_at: date('Y-m-d H:i:s'), code: 'code-abc',
                code_challenge: null, csrf_token: null, updated_at: null,
                refresh_token: null, status: 'AUTHENTICATED',
            ),
        );

        $result = $this->svc->createAuthorizedLogin($this->session, $this->realm, $query);
        self::assertSame('AUTHENTICATED', $result->getStatus()->value);
    }

    public function testCreateAuthorizedLoginUserNotFoundThrows(): void
    {
        $query = [
            'client_id' => 'my-app', 'redirect_uri' => 'http://example.com',
            'response_type' => 'code', 'response_mode' => 'query',
            'scope' => 'openid', 'state' => 'st', 'nonce' => 'nc',
        ];
        $this->clientRepo->method('findByName')->willReturn($this->client);
        $this->userRepo->method('findById')->willReturn(null);

        $this->expectException(AuthenticationFailed::class);
        $this->svc->createAuthorizedLogin($this->session, $this->realm, $query);
    }

    // ── ensureValidCredentials ────────────────────────────────

    public function testEnsureValidCredentialsValidUser(): void
    {
        $this->userRepo->method('findByEmailAndRealmId')->willReturn($this->user);
        $this->secretsService->method('validatePassword')->willReturn(true);

        $result = $this->svc->ensureValidCredentials('r-id', 'test@example.com', 'password');
        self::assertSame($this->user, $result['user']);
        self::assertFalse($result['error']);
    }

    public function testEnsureValidCredentialsInvalidEmailFormat(): void
    {
        $result = $this->svc->ensureValidCredentials('r-id', 'not-an-email', 'pwd');
        self::assertNull($result['user']);
        self::assertSame('invalid email', $result['error']);
    }

    public function testEnsureValidCredentialsEmailNotFound(): void
    {
        $this->userRepo->method('findByEmailAndRealmId')->willReturn(null);
        $result = $this->svc->ensureValidCredentials('r-id', 'test@example.com', 'pwd');
        self::assertNull($result['user']);
        self::assertSame('email not found', $result['error']);
    }

    public function testEnsureValidCredentialsWrongPassword(): void
    {
        $this->userRepo->method('findByEmailAndRealmId')->willReturn($this->user);
        $this->secretsService->method('validatePassword')->willReturn(false);
        $result = $this->svc->ensureValidCredentials('r-id', 'test@example.com', 'wrong');
        self::assertNull($result['user']);
        self::assertSame('invalid password', $result['error']);
    }

    // ── authenticateLogin ─────────────────────────────────────

    public function testAuthenticateLoginHappyPath(): void
    {
        $login = $this->createMock(Login::class);
        $login->method('getScope')->willReturn('openid');
        $login->method('getId')->willReturn('login-1');
        $login->method('getClientId')->willReturn('c-id');

        $this->loginRepo->method('findById')->with('login-1')->willReturn($login);
        $this->clientRepo->method('findById')->with('c-id')->willReturn($this->client);
        $this->sessionOrch->method('create')->willReturn($this->session);
        $this->secretsService->method('generateCode')->willReturn('code-xyz');

        $this->stateMachine->expects($this->once())->method('transition')->willReturn($login);

        $result = $this->svc->authenticateLogin('login-1', $this->user, $this->realm);
        self::assertSame($login, $result['login']);
        self::assertSame($this->session, $result['session']);
    }

    public function testAuthenticateLoginNotFoundThrows(): void
    {
        $this->loginRepo->method('findById')->willReturn(null);
        $this->expectException(StorageFailed::class);
        $this->svc->authenticateLogin('ghost', $this->user, $this->realm);
    }

    // ── logout ────────────────────────────────────────────────

    public function testLogoutValidIdTokenExpiresSession(): void
    {
        $this->tokenService->method('validateToken')->willReturn(true);
        $this->tokenService->method('decodeTokenPayload')->willReturn(['sid' => 's-id']);
        $this->sessionOrch->expects($this->once())->method('expire')->with('s-id');

        $result = $this->svc->logout('valid.id.token', $this->realm);
        self::assertTrue($result);
    }

    public function testLogoutInvalidTokenThrows(): void
    {
        $this->tokenService->method('validateToken')->willReturn(false);
        $this->expectException(ValidationFailed::class);
        $this->svc->logout('bad-token', $this->realm);
    }

    // ── parseValidToken ───────────────────────────────────────

    public function testParseValidTokenReturnsPayload(): void
    {
        $this->tokenService->method('validateToken')->willReturn(true);
        $this->tokenService->method('tokenIsExpired')->willReturn(false);
        $this->tokenService->method('decodeTokenPayload')->willReturn(['sub' => 'u-id']);

        $result = $this->svc->parseValidToken('good-token', $this->realm);
        self::assertSame('u-id', $result['sub']);
    }

    public function testParseValidTokenInvalidThrows(): void
    {
        $this->tokenService->method('validateToken')->willReturn(false);
        $this->expectException(ValidationFailed::class);
        $this->svc->parseValidToken('bad-token', $this->realm);
    }

    public function testParseValidTokenExpiredThrows(): void
    {
        $this->tokenService->method('validateToken')->willReturn(true);
        $this->tokenService->method('tokenIsExpired')->willReturn(true);
        $this->expectException(ValidationFailed::class);
        $this->svc->parseValidToken('expired-token', $this->realm);
    }

    // ── getClientUri ──────────────────────────────────────────

    public function testGetClientUriReturnsUri(): void
    {
        $this->clientRepo->method('findByName')->with('my-app')->willReturn($this->client);
        self::assertSame('http://example.com', $this->svc->getClientUri('my-app'));
    }

    public function testGetClientUriNotFoundThrows(): void
    {
        $this->clientRepo->method('findByName')->willReturn(null);
        $this->expectException(ValidationFailed::class);
        $this->svc->getClientUri('ghost');
    }
}
