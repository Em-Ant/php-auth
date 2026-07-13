<?php

declare(strict_types=1);

namespace AuthServer\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;

class RequestLogger implements MiddlewareInterface
{
    private LoggerInterface $logger;

    public function __construct(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $method = $request->getMethod();
        $uri = (string) $request->getUri();
        $protocol = $request->getServerParams()['SERVER_PROTOCOL'] ?? 'HTTP/1.1';
        $this->logger->info("$method $uri $protocol");
        return $handler->handle($request);
    }
}
