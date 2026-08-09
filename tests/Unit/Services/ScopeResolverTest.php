<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Services;

use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Models\Client;
use AuthServer\Models\Realm;
use AuthServer\Services\ScopeResolver;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

class ScopeResolverTest extends TestCase
{
    private ScopeResolver $resolver;
    private Realm $realm;
    private Client $inheritClient;
    private Client $narrowClient;

    protected function setUp(): void
    {
        $this->resolver = new ScopeResolver(new NullLogger());

        $this->realm = new Realm(
            'r-id', 'test', 'k-id',
            1800, 300, 300, 300, 86400, 1800,
            'openid profile email', '2025-01-01 00:00:00',
        );

        $this->inheritClient = new Client(
            'c-1', 'inherit-app', 'r-id', null, 'https://example.com', false, '2025-01-01 00:00:00',
            null,
        );

        $this->narrowClient = new Client(
            'c-2', 'narrow-app', 'r-id', null, 'https://example.com', false, '2025-01-01 00:00:00',
            'openid profile',
        );
    }

    public function testNullClientScopeInheritsRealm(): void
    {
        $granted = $this->resolver->resolve('openid email', $this->inheritClient, $this->realm, true);
        self::assertSame('openid email', $granted);
    }

    public function testRequestedScopeWithinClientAllowList(): void
    {
        $granted = $this->resolver->resolve('openid profile', $this->narrowClient, $this->realm, true);
        self::assertSame('openid profile', $granted);
    }

    public function testScopeNotInClientAllowListRejected(): void
    {
        $this->expectException(ValidationFailed::class);
        $this->resolver->resolve('openid email', $this->narrowClient, $this->realm, true);
    }

    public function testOpenidAlwaysAllowedEvenIfOmittedFromClientScope(): void
    {
        $client = new Client(
            'c-3', 'openid-less-app', 'r-id', null, 'https://example.com', false, '2025-01-01 00:00:00',
            'profile',
        );
        $granted = $this->resolver->resolve('openid profile', $client, $this->realm, true);
        self::assertSame('openid profile', $granted);
    }

    public function testRequireOpenidMissingOpenidThrows(): void
    {
        $this->expectException(ValidationFailed::class);
        $this->resolver->resolve('profile', $this->inheritClient, $this->realm, true);
    }

    public function testEmptyRequestReturnsEffectiveClientScope(): void
    {
        self::assertSame(
            'openid profile email',
            $this->resolver->resolve('', $this->inheritClient, $this->realm, false)
        );
        self::assertSame(
            'openid profile',
            $this->resolver->resolve('', $this->narrowClient, $this->realm, false)
        );
    }

    public function testScopeInClientButNotInRealmRejected(): void
    {
        $client = new Client(
            'c-4', 'rogue-app', 'r-id', null, 'https://example.com', false, '2025-01-01 00:00:00',
            'openid admin',
        );
        $this->expectException(ValidationFailed::class);
        $this->resolver->resolve('openid admin', $client, $this->realm, true);
    }

    public function testOfflineAccessGatedByClientScope(): void
    {
        $realm = new Realm(
            'r-2', 'test2', 'k-id',
            1800, 300, 300, 300, 86400, 1800,
            'openid profile offline_access', '2025-01-01 00:00:00',
        );
        $client = new Client(
            'c-5', 'web-app', 'r-2', null, 'https://example.com', false, '2025-01-01 00:00:00',
            'openid profile',
        );

        $this->expectException(ValidationFailed::class);
        $this->resolver->resolve('openid offline_access', $client, $realm, true);
    }

    public function testOfflineAccessGrantedWhenClientAllowsIt(): void
    {
        $realm = new Realm(
            'r-3', 'test3', 'k-id',
            1800, 300, 300, 300, 86400, 1800,
            'openid profile offline_access', '2025-01-01 00:00:00',
        );
        $client = new Client(
            'c-6', 'offline-app', 'r-3', null, 'https://example.com', false, '2025-01-01 00:00:00',
            'openid profile offline_access',
        );

        $granted = $this->resolver->resolve('openid offline_access', $client, $realm, true);
        self::assertSame('openid offline_access', $granted);
    }

    public function testClientCredentialsDoesNotRequireOpenid(): void
    {
        $granted = $this->resolver->resolve('profile email', $this->inheritClient, $this->realm, false);
        self::assertSame('profile email', $granted);
    }

    public function testRejectionIsLogged(): void
    {
        $logger = $this->createMock(\Psr\Log\LoggerInterface::class);
        $logger->expects($this->once())
            ->method('info')
            ->with($this->stringContains("scope 'email' not allowed for client 'narrow-app'"));

        $resolver = new ScopeResolver($logger);

        try {
            $resolver->resolve('openid email', $this->narrowClient, $this->realm, true);
            self::fail('expected ValidationFailed');
        } catch (ValidationFailed $e) {
            self::assertSame('invalid scope', $e->getMessage());
        }
    }
}
