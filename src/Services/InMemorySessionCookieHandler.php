<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Interfaces\SessionCookieHandler;
use AuthServer\Models\Realm;
use Psr\Http\Message\ResponseInterface;

class InMemorySessionCookieHandler implements SessionCookieHandler
{
    private ?string $data = null;

    public function read(string $realmName): ?string
    {
        if ($this->data === null) {
            return null;
        }

        $parts = explode('\\', $this->data);
        $cookieRealm = $parts[0];
        $sessionId = $parts[1];

        if ($realmName !== $cookieRealm) {
            return null;
        }

        return $sessionId;
    }

    public function write(Realm $realm, string $sessionId, ResponseInterface $response): ResponseInterface
    {
        $this->data = $realm->getName() . '\\' . $sessionId;
        return $response;
    }

    public function delete(Realm $realm, ResponseInterface $response): ResponseInterface
    {
        $this->data = null;
        return $response;
    }
}
