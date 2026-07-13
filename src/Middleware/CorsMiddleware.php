<?php

declare(strict_types=1);

namespace AuthServer\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Response;

class CorsMiddleware implements MiddlewareInterface
{
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $origin = $request->getHeaderLine('Origin');

        if ($request->getMethod() === 'OPTIONS') {
            $response = new Response();
            $response = $response
                ->withHeader('Access-Control-Allow-Origin', $origin ?: '*')
                ->withHeader(
                    'Access-Control-Allow-Headers',
                    'content-type,accept,origin,authorization'
                )
                ->withHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
                ->withStatus(204);
            if ($origin !== '') {
                $response = $response->withHeader('Access-Control-Allow-Credentials', 'true');
            }
            return $response;
        }

        $response = $handler->handle($request);

        if ($origin !== '') {
            $response = $response
                ->withHeader('Access-Control-Allow-Origin', $origin)
                ->withHeader('Access-Control-Allow-Credentials', 'true');
        } elseif (!$response->hasHeader('Access-Control-Allow-Origin')) {
            $response = $response->withHeader('Access-Control-Allow-Origin', '*');
        }
        if (!$response->hasHeader('Access-Control-Allow-Headers')) {
            $response = $response->withHeader(
                'Access-Control-Allow-Headers',
                'content-type,accept,origin,authorization'
            );
        }
        if (!$response->hasHeader('Access-Control-Allow-Methods')) {
            $response = $response->withHeader(
                'Access-Control-Allow-Methods',
                'GET,POST,OPTIONS'
            );
        }

        return $response;
    }
}
