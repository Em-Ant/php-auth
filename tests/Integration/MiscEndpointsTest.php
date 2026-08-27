<?php

declare(strict_types=1);

namespace AuthServer\Tests\Integration;

use AuthServer\Tests\Support\TestAppFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Factory\ServerRequestFactory;

class MiscEndpointsTest extends TestCase
{
    private static \Slim\App $app;

    public static function setUpBeforeClass(): void
    {
        self::$app = TestAppFactory::createApp();
    }

    private function createRequest(string $method, string $path): ServerRequestInterface
    {
        return (new ServerRequestFactory())->createServerRequest($method, $path);
    }

    private function handle(ServerRequestInterface $request): ResponseInterface
    {
        return self::$app->handle($request);
    }

    public function testHealthReturnsOk(): void
    {
        $res = $this->handle($this->createRequest('GET', '/health'));
        $this->assertEquals(200, $res->getStatusCode());
        $body = json_decode((string) $res->getBody(), true);
        $this->assertEquals('ok', $body['status']);
    }

    public function testReadyReturnsOk(): void
    {
        $res = $this->handle($this->createRequest('GET', '/ready'));
        $this->assertEquals(200, $res->getStatusCode());
        $body = json_decode((string) $res->getBody(), true);
        $this->assertEquals('ok', $body['status']);
    }

    public function test3pCookiesStep1Returns200(): void
    {
        $res = $this->handle($this->createRequest(
            'GET',
            '/realms/test/protocol/openid-connect/3p-cookies/step1.html'
        ));
        $this->assertEquals(200, $res->getStatusCode());
        $this->assertStringContainsString('text/html', $res->getHeaderLine('Content-Type'));
    }

    public function test3pCookiesStep2Returns200(): void
    {
        $res = $this->handle($this->createRequest(
            'GET',
            '/realms/test/protocol/openid-connect/3p-cookies/step2.html'
        ));
        $this->assertEquals(200, $res->getStatusCode());
        $this->assertStringContainsString('text/html', $res->getHeaderLine('Content-Type'));
    }

    public function test3pCookiesInvalidStepReturns400(): void
    {
        $res = $this->handle($this->createRequest(
            'GET',
            '/realms/test/protocol/openid-connect/3p-cookies/invalid.html'
        ));
        $this->assertEquals(400, $res->getStatusCode());
    }

    public function test3pCookiesMissingRealmReturns404(): void
    {
        $res = $this->handle($this->createRequest(
            'GET',
            '/realms/nonexistent/protocol/openid-connect/3p-cookies/step1.html'
        ));
        $this->assertEquals(404, $res->getStatusCode());
    }

    public function testScopeSupportedDerivedFromRealm(): void
    {
        $res = $this->handle($this->createRequest(
            'GET',
            '/realms/test/.well-known/openid-configuration'
        ));
        $this->assertEquals(200, $res->getStatusCode());
        $body = json_decode((string) $res->getBody(), true);
        $this->assertEquals(['openid', 'profile', 'email'], $body['scopes_supported']);
        $this->assertNotContains('acr', $body['scopes_supported']);
        $this->assertNotContains('write', $body['scopes_supported']);
    }

    public function testLoginStatusIframeReturns200(): void
    {
        $res = $this->handle($this->createRequest(
            'GET',
            '/realms/test/protocol/openid-connect/login-status-iframe.html'
        ));
        $this->assertEquals(200, $res->getStatusCode());
        $this->assertStringContainsString('text/html', $res->getHeaderLine('Content-Type'));

        $body = (string) $res->getBody();
        // F-38: the iframe must recompute b64url(SHA-256(session_state)) and
        // compare it against the JS-readable check cookie, not parse a raw id.
        $this->assertStringContainsString('crypto.subtle.digest("SHA-256"', $body);
        $this->assertStringContainsString('AUTH_SESSION_CHECK', $body);
        $this->assertStringNotContainsString('parseSessionCookie', $body);
    }

    public function testLoginStatusIframeInitReturns200(): void
    {
        $res = $this->handle($this->createRequest(
            'GET',
            '/realms/test/protocol/openid-connect/login-status-iframe.html/init?client_id=local&origin=http://localhost:5173'
        ));
        $this->assertEquals(200, $res->getStatusCode());
    }

    public function testLoginStatusIframeInitRejectsUnknownClient(): void
    {
        $res = $this->handle($this->createRequest(
            'GET',
            '/realms/test/protocol/openid-connect/login-status-iframe.html/init?client_id=evil&origin=http://localhost:5173'
        ));
        $this->assertEquals(400, $res->getStatusCode());
    }

    public function testLoginStatusIframeInitRejectsForeignOrigin(): void
    {
        $res = $this->handle($this->createRequest(
            'GET',
            '/realms/test/protocol/openid-connect/login-status-iframe.html/init?client_id=local&origin=https://evil.com'
        ));
        $this->assertEquals(400, $res->getStatusCode());
    }

    public function testLoginStatusIframeInitRejectsClientFromOtherRealm(): void
    {
        $res = $this->handle($this->createRequest(
            'GET',
            '/realms/test/protocol/openid-connect/login-status-iframe.html/init?client_id=playground&origin=http://localhost:5173'
        ));
        $this->assertEquals(400, $res->getStatusCode());
    }

    public function testLoginStatusIframeInitRejectsMissingParams(): void
    {
        $res = $this->handle($this->createRequest(
            'GET',
            '/realms/test/protocol/openid-connect/login-status-iframe.html/init'
        ));
        $this->assertEquals(400, $res->getStatusCode());
    }
}
