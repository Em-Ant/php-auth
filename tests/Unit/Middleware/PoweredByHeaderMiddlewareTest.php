<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Middleware;

use AuthServer\Middleware\PoweredByHeaderMiddleware;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Response;

class PoweredByHeaderMiddlewareTest extends TestCase
{
    private PoweredByHeaderMiddleware $middleware;

    protected function setUp(): void
    {
        $this->middleware = new PoweredByHeaderMiddleware();
    }

    public function testStripsPoweredByHeader(): void
    {
        $response = $this->processWith((new Response())->withHeader('X-Powered-By', 'PHP/8.3.6'));

        self::assertFalse($response->hasHeader('X-Powered-By'));
    }

    public function testPassesThroughWhenHeaderAbsent(): void
    {
        $response = $this->processWith(new Response());

        self::assertSame(200, $response->getStatusCode());
        self::assertFalse($response->hasHeader('X-Powered-By'));
    }

    private function processWith(ResponseInterface $upstream): ResponseInterface
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($upstream);

        return $this->middleware->process($request, $handler);
    }
}
