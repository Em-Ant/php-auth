<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Services;

use AuthServer\Models\Realm;
use AuthServer\Services\HttpSessionCookieHandler;
use AuthServer\Services\Base64Utils;
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

        $cookies = $result->getHeader('Set-Cookie');
        self::assertCount(2, $cookies);

        $sessionCookie = $cookies[0];
        self::assertStringStartsWith('AUTH_SESSION=web%5Csession-123', $sessionCookie);
        self::assertStringContainsString('Path=/realms/web', $sessionCookie);
        self::assertStringContainsString('Secure', $sessionCookie);
        self::assertStringContainsString('SameSite=None', $sessionCookie);
        self::assertStringContainsString('HttpOnly', $sessionCookie);

        $checkCookie = $cookies[1];
        // F-38: the JS-readable check cookie must hold a salted hash of the
        // session id, never the id itself, so the login-status iframe can
        // verify client-supplied session_state without exposing the id to JS.
        $expectedCheck = Base64Utils::b64UrlEncode(hash('sha256', 'session-123', true));
        self::assertStringStartsWith('AUTH_SESSION_CHECK=' . $expectedCheck, $checkCookie);
        self::assertStringNotContainsString('session-123', $checkCookie);
        self::assertStringContainsString('Path=/realms/web', $checkCookie);
        self::assertStringContainsString('Secure', $checkCookie);
        self::assertStringContainsString('SameSite=None', $checkCookie);
        self::assertStringNotContainsString('HttpOnly', $checkCookie);
    }

    public function testWriteHonoursMountPath(): void
    {
        $handler = new HttpSessionCookieHandler('/auth', 'localhost');
        $response = (new ResponseFactory())->createResponse();

        $cookies = $handler->write($this->realm, 'session-123', $response)->getHeader('Set-Cookie');
        self::assertStringContainsString('Path=/auth/realms/web', $cookies[0]);
        self::assertStringContainsString('Path=/auth/realms/web', $cookies[1]);
    }

    public function testDeleteAddsExpiredSetCookieHeader(): void
    {
        $response = (new ResponseFactory())->createResponse();
        $result = $this->handler->delete($this->realm, $response);

        $cookies = $result->getHeader('Set-Cookie');
        self::assertCount(2, $cookies);

        self::assertStringStartsWith('AUTH_SESSION=', $cookies[0]);
        self::assertStringContainsString('Expires=Thu, 01 Jan 1970', $cookies[0]);
        self::assertStringContainsString('SameSite=None', $cookies[0]);
        self::assertStringContainsString('HttpOnly', $cookies[0]);

        self::assertStringStartsWith('AUTH_SESSION_CHECK=', $cookies[1]);
        self::assertStringContainsString('Expires=Thu, 01 Jan 1970', $cookies[1]);
        self::assertStringContainsString('SameSite=None', $cookies[1]);
        self::assertStringNotContainsString('HttpOnly', $cookies[1]);
    }
}
