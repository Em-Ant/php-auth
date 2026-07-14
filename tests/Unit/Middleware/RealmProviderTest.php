<?php

declare(strict_types=1);

namespace AuthServer\Tests\Unit\Middleware;

use AuthServer\Interfaces\RealmRepository;
use AuthServer\Middleware\RealmProvider;
use AuthServer\Models\Realm;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Exception\HttpNotFoundException;
use Slim\Routing\Route;
use Slim\Routing\RouteContext;

class RealmProviderTest extends TestCase
{
    private RealmRepository $repo;
    private RealmProvider $middleware;
    private Realm $realm;

    protected function setUp(): void
    {
        $this->repo = $this->createMock(RealmRepository::class);
        $this->middleware = new RealmProvider($this->repo);
        $this->realm = new Realm(
            'r-id', 'web', 'k-id', 1800, 300, 300, 300, 86400, 1800,
            'openid', '2025-01-01 00:00:00',
        );
    }

    public function testValidRealmSetsAttributeAndPassesThrough(): void
    {
        $route = $this->createMock(Route::class);
        $route->method('getArgument')->with('realm')->willReturn('web');

        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getAttribute')->with(RouteContext::ROUTE)->willReturn($route);

        $response = $this->createMock(ResponseInterface::class);

        $this->repo->method('findByName')->with('web')->willReturn($this->realm);

        $request->expects(self::once())
            ->method('withAttribute')
            ->with(Realm::class, $this->realm)
            ->willReturn($request);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects(self::once())->method('handle')->with($request)->willReturn($response);

        $result = $this->middleware->process($request, $handler);
        self::assertSame($response, $result);
    }

    public function testMissingRouteThrows404(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getAttribute')->with(RouteContext::ROUTE)->willReturn(null);

        $this->expectException(HttpNotFoundException::class);
        $this->middleware->process($request, $this->createMock(RequestHandlerInterface::class));
    }

    public function testRealmNotFoundThrows404(): void
    {
        $route = $this->createMock(Route::class);
        $route->method('getArgument')->with('realm')->willReturn('ghost');

        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getAttribute')->with(RouteContext::ROUTE)->willReturn($route);

        $this->repo->method('findByName')->with('ghost')->willReturn(null);

        $this->expectException(HttpNotFoundException::class);
        $this->middleware->process($request, $this->createMock(RequestHandlerInterface::class));
    }
}
