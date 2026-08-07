<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Services;

use AuthServer\Models\Realm;
use AuthServer\Services\HttpSessionCookieHandler;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\ServerRequestFactory;

class HttpSessionCookieHandlerTest extends TestCase
{
    private HttpSessionCookieHandler $handler;
    private Realm $realm;

    protected function setUp(): void
    {
        $this->handler = new HttpSessionCookieHandler('', 'localhost');
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
    }

    private function requestWithCookie(?string $cookie): ServerRequestInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest(
            'GET',
            'http://localhost/realms/web/protocol/openid-connect/auth'
        );

        if ($cookie !== null) {
            $request = $request->withCookieParams(['AUTH_SESSION' => $cookie]);
        }

        return $request;
    }

    public function testReadReturnsNullWhenNoCookie(): void
    {
        self::assertNull($this->handler->read($this->requestWithCookie(null), 'web'));
    }

    public function testReadReturnsSessionIdForMatchingRealm(): void
    {
        $request = $this->requestWithCookie('web\\session-123');
        self::assertSame('session-123', $this->handler->read($request, 'web'));
    }

    public function testReadReturnsNullForWrongRealm(): void
    {
        $request = $this->requestWithCookie('web\\session-123');
        self::assertNull($this->handler->read($request, 'test'));
    }

    public function testReadReturnsNullForMalformedCookie(): void
    {
        $request = $this->requestWithCookie('web');
        self::assertNull($this->handler->read($request, 'web'));
    }

    public function testWriteAddsSetCookieHeader(): void
    {
        $response = (new ResponseFactory())->createResponse();
        $result = $this->handler->write($this->realm, 'session-123', $response);

        $cookie = $result->getHeaderLine('Set-Cookie');
        self::assertStringContainsString('AUTH_SESSION=web%5Csession-123', $cookie);
        self::assertStringContainsString('Path=/realms/web', $cookie);
        self::assertStringContainsString('Secure', $cookie);
        self::assertStringContainsString('SameSite=None', $cookie);
    }

    public function testWriteHonoursMountPath(): void
    {
        $handler = new HttpSessionCookieHandler('/auth', 'localhost');
        $response = (new ResponseFactory())->createResponse();

        $cookie = $handler->write($this->realm, 'session-123', $response)->getHeaderLine('Set-Cookie');
        self::assertStringContainsString('Path=/auth/realms/web', $cookie);
    }

    public function testDeleteAddsExpiredSetCookieHeader(): void
    {
        $response = (new ResponseFactory())->createResponse();
        $result = $this->handler->delete($this->realm, $response);

        $cookie = $result->getHeaderLine('Set-Cookie');
        self::assertStringStartsWith('AUTH_SESSION=', $cookie);
        self::assertStringContainsString('Expires=Thu, 01 Jan 1970', $cookie);
        self::assertStringContainsString('SameSite=None', $cookie);
    }
}
