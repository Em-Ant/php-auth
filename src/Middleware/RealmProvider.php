<?php

declare(strict_types=1);

namespace AuthServer\Middleware;

use AuthServer\Interfaces\RealmRepository;
use AuthServer\Models\Realm;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Exception\HttpNotFoundException;
use Slim\Routing\RouteContext;

class RealmProvider implements MiddlewareInterface
{
    private RealmRepository $realms;

    public function __construct(RealmRepository $repo)
    {
        $this->realms = $repo;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $route = $request->getAttribute(RouteContext::ROUTE);
        $realm_name = $route !== null ? $route->getArgument('realm') : null;

        if ($realm_name === null) {
            throw new HttpNotFoundException($request, 'realm parameter missing');
        }

        $realm = $this->realms->findByName($realm_name);

        if (!$realm) {
            throw new HttpNotFoundException($request, 'realm not found');
        }

        return $handler->handle($request->withAttribute(Realm::class, $realm));
    }
}
