<?php

declare(strict_types=1);

namespace AuthServer\Models;

/**
 * Flavor of refresh token: the regular SSO refresh token or the long-lived
 * offline one. The kind decides both the `typ` claim and the TTL applied.
 */
enum RefreshTokenKind: string
{
    case Sso = 'Refresh';
    case Offline = 'Offline';

    public function expiresIn(Realm $realm): int
    {
        return $this === self::Offline
            ? $realm->getOfflineRefreshTokenExpiresIn()
            : $realm->getRefreshTokenExpiresIn();
    }
}
