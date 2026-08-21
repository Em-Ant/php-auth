<?php

declare(strict_types=1);

namespace AuthServer\Tests\Support;

/**
 * Inserts minimal parent rows (realms, clients) so tests can attach roles,
 * users, sessions or logins without depending on db/seed.sql.
 */
final class RealmFixture
{
    public static function createRealm(\PDO $pdo, string $id, string $name): void
    {
        $pdo->exec(
            "INSERT INTO realms (id, name, keys_id, refresh_token_expires_in,
                access_token_expires_in, pending_login_expires_in,
                authenticated_login_expires_in, session_expires_in,
                idle_session_expires_in)
             VALUES ('$id', '$name', 'k', 1800, 300, 300, 300, 3600, 1800)"
        );
    }

    public static function createClient(
        \PDO $pdo,
        string $id,
        string $name,
        string $realmId
    ): void {
        $pdo->exec(
            "INSERT INTO clients (id, name, uri, realm_id)
             VALUES ('$id', '$name', 'https://$name.example.com', '$realmId')"
        );
    }
}
