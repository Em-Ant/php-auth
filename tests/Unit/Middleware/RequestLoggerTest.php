<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Middleware;

use AuthServer\Middleware\RequestLogger;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;

class RequestLoggerTest extends TestCase
{
    public function testLogsMethodUriAndProtocol(): void
    {
        $uri = $this->createMock(UriInterface::class);
        $uri->method('__toString')->willReturn('/realms/test/auth');

        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('GET');
        $request->method('getUri')->willReturn($uri);
        $request->method('getServerParams')->willReturn(['SERVER_PROTOCOL' => 'HTTP/1.1']);

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('info')
            ->with('GET /realms/test/auth HTTP/1.1');

        $middleware = new RequestLogger($logger);

        $response = $this->createMock(ResponseInterface::class);
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($response);

        $result = $middleware->process($request, $handler);
        self::assertSame($response, $result);
    }
}
