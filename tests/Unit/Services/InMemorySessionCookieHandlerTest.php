<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Services;

use AuthServer\Models\Realm;
use AuthServer\Services\InMemorySessionCookieHandler;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Factory\ServerRequestFactory;

class InMemorySessionCookieHandlerTest extends TestCase
{
    private InMemorySessionCookieHandler $handler;
    private Realm $realm;
    private ResponseInterface $response;
    private ServerRequestInterface $request;

    protected function setUp(): void
    {
        $this->handler = new InMemorySessionCookieHandler();
        $this->realm = new Realm(
            'realm-id',
            'web',
            'key-id',
            1800,
            300,
            300,
            300,
            86400,
            1800,
            'openid profile email',
            '2025-01-01 00:00:00',
        );
        $this->response = $this->createMock(ResponseInterface::class);
        $this->request = (new ServerRequestFactory())->createServerRequest(
            'GET',
            'http://localhost/realms/web/protocol/openid-connect/auth'
        );
    }

    public function testReadReturnsNullWhenNothingWritten(): void
    {
        self::assertNull($this->handler->read($this->request, 'web'));
    }

    public function testWriteThenReadReturnsSessionId(): void
    {
        $result = $this->handler->write($this->realm, 'session-123', $this->response);
        self::assertSame($this->response, $result);
        self::assertSame('session-123', $this->handler->read($this->request, 'web'));
    }

    public function testReadReturnsNullForWrongRealm(): void
    {
        $this->handler->write($this->realm, 'session-123', $this->response);
        self::assertNull($this->handler->read($this->request, 'test'));
    }

    public function testDeleteClearsData(): void
    {
        $this->handler->write($this->realm, 'session-123', $this->response);
        $result = $this->handler->delete($this->realm, $this->response);
        self::assertSame($this->response, $result);
        self::assertNull($this->handler->read($this->request, 'web'));
    }

    public function testWriteOverwritesPreviousData(): void
    {
        $this->handler->write($this->realm, 'session-123', $this->response);
        $otherRealm = new Realm('realm-2', 'test', 'key-2', 1800, 300, 300, 300, 86400, 1800, 'openid profile', '2025-01-01 00:00:00');
        $this->handler->write($otherRealm, 'session-456', $this->response);
        self::assertNull($this->handler->read($this->request, 'web'));
        self::assertSame('session-456', $this->handler->read($this->request, 'test'));
    }
}
