<?php

declare(strict_types=1);

namespace AuthServer\Interfaces;

use AuthServer\Models\Realm;

interface SessionCookieHandler
{
    public function read(string $realmName): ?string;
    public function write(Realm $realm, string $sessionId): void;
    public function delete(Realm $realm): void;
}
