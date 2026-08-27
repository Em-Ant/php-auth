<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Middleware;

use AuthServer\Middleware\CorsMiddleware;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Response;

class CorsMiddlewareTest extends TestCase
{
    private CorsMiddleware $middleware;

    protected function setUp(): void
    {
        // Default (no args) lists '*': reflect any origin (backward compat).
        $this->middleware = new CorsMiddleware();
    }

    public function testAllowedOriginIsReflectedWithCredentials(): void
    {
        $request = $this->createRequestWithOrigin('https://example.com');
        $innerResponse = new Response();
        $handler = $this->createHandlerReturning($innerResponse);

        $response = $this->middleware->process($request, $handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('https://example.com', $response->getHeaderLine('Access-Control-Allow-Origin'));
        self::assertSame('true', $response->getHeaderLine('Access-Control-Allow-Credentials'));
        self::assertSame(
            'content-type,accept,origin,authorization',
            $response->getHeaderLine('Access-Control-Allow-Headers'),
        );
        self::assertSame('GET,POST,PUT,DELETE,OPTIONS', $response->getHeaderLine('Access-Control-Allow-Methods'));
    }

    public function testOptionsForAllowedOriginReturns204WithCorsHeaders(): void
    {
        $request = $this->createRequestWithOrigin('https://example.com', 'OPTIONS');
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects(self::never())->method('handle');

        $response = $this->middleware->process($request, $handler);

        self::assertSame(204, $response->getStatusCode());
        self::assertSame('https://example.com', $response->getHeaderLine('Access-Control-Allow-Origin'));
        self::assertSame('true', $response->getHeaderLine('Access-Control-Allow-Credentials'));
        self::assertSame(
            'content-type,accept,origin,authorization',
            $response->getHeaderLine('Access-Control-Allow-Headers'),
        );
        self::assertSame('GET,POST,PUT,DELETE,OPTIONS', $response->getHeaderLine('Access-Control-Allow-Methods'));
    }

    public function testRequestWithoutOriginGetsNoCorsHeaders(): void
    {
        $request = $this->createRequestWithOrigin('');
        $innerResponse = new Response();
        $handler = $this->createHandlerReturning($innerResponse);

        $response = $this->middleware->process($request, $handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertFalse($response->hasHeader('Access-Control-Allow-Origin'));
        self::assertFalse($response->hasHeader('Access-Control-Allow-Credentials'));
    }

    public function testOptionsWithoutOriginGetsNoCorsHeaders(): void
    {
        $request = $this->createRequestWithOrigin('', 'OPTIONS');
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects(self::never())->method('handle');

        $response = $this->middleware->process($request, $handler);

        self::assertSame(204, $response->getStatusCode());
        self::assertFalse($response->hasHeader('Access-Control-Allow-Origin'));
    }

    public function testAllowlistedOriginIsReflectedWithCredentials(): void
    {
        $middleware = new CorsMiddleware(['https://app.example.com', 'https://other.com']);
        $request = $this->createRequestWithOrigin('https://app.example.com');
        $innerResponse = new Response();
        $handler = $this->createHandlerReturning($innerResponse);

        $response = $middleware->process($request, $handler);

        self::assertSame('https://app.example.com', $response->getHeaderLine('Access-Control-Allow-Origin'));
        self::assertSame('true', $response->getHeaderLine('Access-Control-Allow-Credentials'));
    }

    public function testDisallowedOriginGetsNoCorsHeaders(): void
    {
        $middleware = new CorsMiddleware(['https://app.example.com']);
        $request = $this->createRequestWithOrigin('https://evil.example.net');
        $innerResponse = new Response();
        $handler = $this->createHandlerReturning($innerResponse);

        $response = $middleware->process($request, $handler);

        self::assertFalse($response->hasHeader('Access-Control-Allow-Origin'));
        self::assertFalse($response->hasHeader('Access-Control-Allow-Credentials'));
        self::assertFalse($response->hasHeader('Access-Control-Allow-Headers'));
        self::assertFalse($response->hasHeader('Access-Control-Allow-Methods'));
    }

    public function testUnlistedOriginPreflightGetsNoCorsHeaders(): void
    {
        $middleware = new CorsMiddleware(['https://app.example.com']);
        $request = $this->createRequestWithOrigin('https://evil.example.net', 'OPTIONS');
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects(self::never())->method('handle');

        $response = $middleware->process($request, $handler);

        self::assertSame(204, $response->getStatusCode());
        self::assertFalse($response->hasHeader('Access-Control-Allow-Origin'));
        self::assertFalse($response->hasHeader('Access-Control-Allow-Credentials'));
    }

    public function testEmptyListDeniesAllOrigins(): void
    {
        $middleware = new CorsMiddleware([]);
        $request = $this->createRequestWithOrigin('https://anything.example');
        $innerResponse = new Response();
        $handler = $this->createHandlerReturning($innerResponse);

        $response = $middleware->process($request, $handler);

        self::assertFalse($response->hasHeader('Access-Control-Allow-Origin'));
        self::assertFalse($response->hasHeader('Access-Control-Allow-Credentials'));
    }

    public function testDisallowedOriginStripsHardcodedInnerOriginHeader(): void
    {
        // Inner handlers (e.g. JsonResponse) may set ACAO '*' themselves; the
        // middleware must strip them for disallowed origins, not leave them.
        $middleware = new CorsMiddleware(['https://app.example.com']);
        $request = $this->createRequestWithOrigin('https://evil.example.net');
        $innerResponse = (new Response())->withHeader('Access-Control-Allow-Origin', '*');
        $handler = $this->createHandlerReturning($innerResponse);

        $response = $middleware->process($request, $handler);

        self::assertFalse($response->hasHeader('Access-Control-Allow-Origin'));
    }

    private function createRequestWithOrigin(string $origin, string $method = 'GET'): ServerRequestInterface
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn($method);
        $request->method('getHeaderLine')->with('Origin')->willReturn($origin);
        return $request;
    }

    private function createHandlerReturning(ResponseInterface $response): RequestHandlerInterface
    {
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($response);
        return $handler;
    }
}
