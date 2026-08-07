<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Interfaces\SessionCookieHandler;
use AuthServer\Models\Realm;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class HttpSessionCookieHandler implements SessionCookieHandler
{
    public function __construct(
        private readonly string $mountPath,
        private readonly string $serverName,
    ) {
    }

    public function read(ServerRequestInterface $request, string $realmName): ?string
    {
        $cookies = $request->getCookieParams();
        $cookie = $cookies['AUTH_SESSION'] ?? null;

        if ($cookie === null) {
            return null;
        }

        $parts = explode('\\', $cookie);
        if (count($parts) < 2 || $realmName !== $parts[0]) {
            return null;
        }

        return $parts[1];
    }

    public function write(Realm $realm, string $sessionId, ResponseInterface $response): ResponseInterface
    {
        $value = $realm->getName() . '\\' . $sessionId;
        $cookie = $this->buildSetCookie($realm, $value, time() + $realm->getSessionExpiresIn());

        return $response->withAddedHeader('Set-Cookie', $cookie);
    }

    public function delete(Realm $realm, ResponseInterface $response): ResponseInterface
    {
        $cookie = $this->buildSetCookie($realm, '', 1);

        return $response->withAddedHeader('Set-Cookie', $cookie);
    }

    private function buildSetCookie(Realm $realm, string $value, int $expires): string
    {
        $path = ($this->mountPath ?: '') . '/realms/' . $realm->getName();

        return 'AUTH_SESSION=' . rawurlencode($value)
            . '; Path=' . $path
            . '; Domain=' . $this->serverName
            . '; Expires=' . gmdate('D, d M Y H:i:s T', $expires)
            . '; Max-Age=' . max(0, $expires - time())
            . '; Secure'
            . '; SameSite=None';
    }
}
