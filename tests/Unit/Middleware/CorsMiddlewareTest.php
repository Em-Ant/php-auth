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
        $this->middleware = new CorsMiddleware();
    }

    public function testOptionsRequestReturns204WithCorsHeaders(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('OPTIONS');
        $request->method('getHeaderLine')->with('Origin')->willReturn('');

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects(self::never())->method('handle');

        $response = $this->middleware->process($request, $handler);

        self::assertSame(204, $response->getStatusCode());
        self::assertSame('*', $response->getHeaderLine('Access-Control-Allow-Origin'));
        self::assertSame(
            'content-type,accept,origin,authorization',
            $response->getHeaderLine('Access-Control-Allow-Headers'),
        );
        self::assertSame('GET,POST,OPTIONS', $response->getHeaderLine('Access-Control-Allow-Methods'));
    }

    public function testOptionsRequestWithOriginIncludesCredentials(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('OPTIONS');
        $request->method('getHeaderLine')->with('Origin')->willReturn('https://example.com');

        $handler = $this->createMock(RequestHandlerInterface::class);

        $response = $this->middleware->process($request, $handler);
        self::assertSame(204, $response->getStatusCode());
        self::assertSame('https://example.com', $response->getHeaderLine('Access-Control-Allow-Origin'));
        self::assertSame('true', $response->getHeaderLine('Access-Control-Allow-Credentials'));
    }

    public function testGetRequestPassesToHandlerAndAddsWildcardOrigin(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('GET');
        $request->method('getHeaderLine')->with('Origin')->willReturn('');

        $innerResponse = new Response();
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($innerResponse);

        $response = $this->middleware->process($request, $handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('*', $response->getHeaderLine('Access-Control-Allow-Origin'));
    }

    public function testGetRequestWithOriginSetsSpecificOrigin(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('GET');
        $request->method('getHeaderLine')->with('Origin')->willReturn('https://client.example.com');

        $innerResponse = new Response();
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($innerResponse);

        $response = $this->middleware->process($request, $handler);

        self::assertSame('https://client.example.com', $response->getHeaderLine('Access-Control-Allow-Origin'));
        self::assertSame('true', $response->getHeaderLine('Access-Control-Allow-Credentials'));
    }
}
