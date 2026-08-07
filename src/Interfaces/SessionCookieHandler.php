<?php

declare(strict_types=1);

namespace AuthServer\Interfaces;

use AuthServer\Models\Realm;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

interface SessionCookieHandler
{
    public function read(ServerRequestInterface $request, string $realmName): ?string;
    /** @return ResponseInterface with Set-Cookie header added */
    public function write(Realm $realm, string $sessionId, ResponseInterface $response): ResponseInterface;
    /** @return ResponseInterface with Set-Cookie (expired) header added */
    public function delete(Realm $realm, ResponseInterface $response): ResponseInterface;
}
