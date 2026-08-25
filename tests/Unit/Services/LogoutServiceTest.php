<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Services;

use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\ClientRepository as IClientRepo;
use AuthServer\Models\Client;
use AuthServer\Models\Realm;
use AuthServer\Services\LogoutService;
use AuthServer\Services\SessionOrchestrator;
use AuthServer\Services\TokenValidator;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

class LogoutServiceTest extends TestCase
{
    private TokenValidator $tokenValidator;
    private SessionOrchestrator $sessionOrch;
    private IClientRepo $clientRepo;
    private LogoutService $svc;
    private Realm $realm;
    private Client $client;

    protected function setUp(): void
    {
        $this->tokenValidator = $this->createMock(TokenValidator::class);
        $this->sessionOrch = $this->createMock(SessionOrchestrator::class);
        $this->clientRepo = $this->createMock(IClientRepo::class);

        $this->svc = new LogoutService(
            $this->tokenValidator,
            $this->sessionOrch,
            $this->clientRepo,
            $this->createMock(LoggerInterface::class),
        );

        $this->realm = new Realm(
            'r-id', 'test', 'k-id',
            1800, 300, 300, 300, 86400, 1800,
            'openid profile', '2025-01-01 00:00:00',
        );

        $this->client = new Client(
            'c-id', 'my-app', 'r-id', null, 'https://example.com', false, '2025-01-01 00:00:00',
        );
    }

    // ── logout ────────────────────────────────────────────────

    public function testLogoutValidIdTokenExpiresSession(): void
    {
        $this->tokenValidator->method('validateIdTokenHint')->willReturn(['sid' => 's-id']);
        $this->sessionOrch->expects($this->once())->method('expire')->with('s-id');

        $result = $this->svc->logout('valid.id.token', $this->realm);
        self::assertTrue($result);
    }

    public function testLogoutInvalidTokenThrows(): void
    {
        $this->tokenValidator->method('validateIdTokenHint')->willReturn(null);
        $this->expectException(ValidationFailed::class);
        $this->svc->logout('bad-token', $this->realm);
    }

    // ── validateLogoutRedirectUri ─────────────────────────────

    public function testValidateLogoutRedirectUriAcceptsRegisteredTarget(): void
    {
        $this->tokenValidator->method('decodeClaimsOnly')->willReturn(['azp' => 'my-app']);
        $this->clientRepo->method('findByName')->with('my-app')->willReturn($this->client);

        $result = $this->svc->validateLogoutRedirectUri('id-token', 'https://example.com');
        self::assertSame('https://example.com', $result);
    }

    public function testValidateLogoutRedirectUriRejectsSubpathTarget(): void
    {
        $this->tokenValidator->method('decodeClaimsOnly')->willReturn(['azp' => 'my-app']);
        $this->clientRepo->method('findByName')->with('my-app')->willReturn($this->client);

        $result = $this->svc->validateLogoutRedirectUri('id-token', 'https://example.com/logged-out');
        self::assertNull($result);
    }

    public function testValidateLogoutRedirectUriFallsBackToAud(): void
    {
        $this->tokenValidator->method('decodeClaimsOnly')->willReturn(['aud' => 'my-app']);
        $this->clientRepo->method('findByName')->with('my-app')->willReturn($this->client);

        $result = $this->svc->validateLogoutRedirectUri('id-token', 'https://example.com');
        self::assertSame('https://example.com', $result);
    }

    public function testValidateLogoutRedirectUriRejectsUnregisteredTarget(): void
    {
        $this->tokenValidator->method('decodeClaimsOnly')->willReturn(['azp' => 'my-app']);
        $this->clientRepo->method('findByName')->with('my-app')->willReturn($this->client);

        $result = $this->svc->validateLogoutRedirectUri('id-token', 'https://evil.com');
        self::assertNull($result);
    }

    public function testValidateLogoutRedirectUriEmptyTargetReturnsNull(): void
    {
        $result = $this->svc->validateLogoutRedirectUri('id-token', '');
        self::assertNull($result);
    }

    public function testValidateLogoutRedirectUriWithoutClientClaimReturnsNull(): void
    {
        $this->tokenValidator->method('decodeClaimsOnly')->willReturn(['sid' => 's-id']);
        $this->clientRepo->method('findByName')->with('my-app')->willReturn($this->client);

        $result = $this->svc->validateLogoutRedirectUri('id-token', 'https://example.com');
        self::assertNull($result);
    }

    public function testValidateLogoutRedirectUriUnknownClientReturnsNull(): void
    {
        $this->tokenValidator->method('decodeClaimsOnly')->willReturn(['azp' => 'ghost']);
        $this->clientRepo->method('findByName')->with('ghost')->willReturn(null);

        $result = $this->svc->validateLogoutRedirectUri('id-token', 'https://example.com');
        self::assertNull($result);
    }

    public function testValidateLogoutRedirectUriUndecodableTokenReturnsNull(): void
    {
        $result = $this->svc->validateLogoutRedirectUri('not-a-jwt', 'https://example.com');
        self::assertNull($result);
    }
}
