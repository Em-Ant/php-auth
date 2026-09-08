<?php

declare(strict_types=1);

namespace AuthServer\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Strips the PHP-version-disclosing `X-Powered-By` response header (P-09).
 *
 * The value is emitted by PHP itself (`expose_php`), not by Slim, so the
 * entrypoint also disables it via `ini_set`; this middleware covers the
 * PSR-7 layer and any SAPI header still queued at runtime.
 */
final class PoweredByHeaderMiddleware implements MiddlewareInterface
{
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (function_exists('header_remove')) {
            @header_remove('X-Powered-By');
        }

        $response = $handler->handle($request);

        if ($response->hasHeader('X-Powered-By')) {
            return $response->withoutHeader('X-Powered-By');
        }

        return $response;
    }
}
