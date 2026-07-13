<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Interfaces\SessionCookieHandler;
use AuthServer\Models\Realm;
use Psr\Http\Message\ResponseInterface;

class HttpSessionCookieHandler implements SessionCookieHandler
{
    public function __construct(
        private readonly string $mountPath,
        private readonly string $serverName,
    ) {
    }

    public function read(string $realmName): ?string
    {
        $cookie = $_COOKIE['AUTH_SESSION'] ?? null;

        if ($cookie === null) {
            return null;
        }

        $parts = explode('\\', $cookie);
        $cookieRealm = $parts[0];
        $sessionId = $parts[1];

        if ($realmName !== $cookieRealm) {
            return null;
        }

        return $sessionId;
    }

    public function write(Realm $realm, string $sessionId, ResponseInterface $response): ResponseInterface
    {
        $path = ($this->mountPath ?: '') . '/realms/' . $realm->getName();

        $value = 'AUTH_SESSION=' . rawurlencode($realm->getName() . '\\' . $sessionId)
            . '; Expires=' . gmdate('D, d M Y H:i:s T', time() + $realm->getSessionExpiresIn())
            . '; Path=' . $path
            . '; Domain=' . $this->serverName
            . '; Secure'
            . '; SameSite=None';

        return $response->withAddedHeader('Set-Cookie', $value);
    }

    public function delete(Realm $realm, ResponseInterface $response): ResponseInterface
    {
        $path = ($this->mountPath ?: '') . '/realms/' . $realm->getName();

        $value = 'AUTH_SESSION='
            . '; Expires=' . gmdate('D, d M Y H:i:s T', 1)
            . '; Path=' . $path
            . '; Domain=' . $this->serverName
            . '; Secure'
            . '; SameSite=None';

        return $response->withAddedHeader('Set-Cookie', $value);
    }
}
