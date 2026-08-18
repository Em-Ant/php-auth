<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Interfaces\SessionCookieHandler;
use AuthServer\Models\Realm;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class HttpSessionCookieHandler implements SessionCookieHandler
{
    public const SESSION_COOKIE_NAME = 'AUTH_SESSION';
    public const CHECK_SESSION_COOKIE_NAME = 'AUTH_SESSION_CHECK';

    public function __construct(
        private readonly string $mountPath,
        private readonly string $serverName,
    ) {
    }

    public function read(ServerRequestInterface $request, string $realmName): ?string
    {
        $cookies = $request->getCookieParams();
        $cookie = $cookies[self::SESSION_COOKIE_NAME] ?? null;

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
        $value = $this->cookieValue($realm, $sessionId);
        $expires = time() + $realm->getSessionExpiresIn();

        $response = $response->withAddedHeader(
            'Set-Cookie',
            $this->buildSetCookie($realm, self::SESSION_COOKIE_NAME, $value, $expires, true)
        );

        return $response->withAddedHeader(
            'Set-Cookie',
            $this->buildSetCookie($realm, self::CHECK_SESSION_COOKIE_NAME, $value, $expires, false)
        );
    }

    public function delete(Realm $realm, ResponseInterface $response): ResponseInterface
    {
        $response = $response->withAddedHeader(
            'Set-Cookie',
            $this->buildSetCookie($realm, self::SESSION_COOKIE_NAME, '', 1, true)
        );

        return $response->withAddedHeader(
            'Set-Cookie',
            $this->buildSetCookie($realm, self::CHECK_SESSION_COOKIE_NAME, '', 1, false)
        );
    }

    private function cookieValue(Realm $realm, string $sessionId): string
    {
        return $realm->getName() . '\\' . $sessionId;
    }

    private function buildSetCookie(
        Realm $realm,
        string $name,
        string $value,
        int $expires,
        bool $httpOnly
    ): string {
        $path = ($this->mountPath ?: '') . '/realms/' . $realm->getName();

        return $name . '=' . rawurlencode($value)
            . '; Path=' . $path
            . '; Domain=' . $this->serverName
            . '; Expires=' . gmdate('D, d M Y H:i:s T', $expires)
            . '; Max-Age=' . max(0, $expires - time())
            . '; Secure'
            . '; SameSite=None'
            . ($httpOnly ? '; HttpOnly' : '');
    }
}
