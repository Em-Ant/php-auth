<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Interfaces\SessionCookieHandler;
use AuthServer\Models\Realm;

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

    public function write(Realm $realm, string $sessionId): void
    {
        $this->data = $realm->getName() . '\\' . $sessionId;
    }

    public function delete(Realm $realm): void
    {
        $this->data = null;
    }
}
