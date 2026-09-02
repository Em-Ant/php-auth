<?php

declare(strict_types=1);

namespace AuthServer\Tests\Support;

use PDO;

use function AuthServer\getGuid;

/**
 * Inserts minimal auth-flow rows (users, sessions, logins, offline_sessions,
 * token_blacklist) so tests avoid repeating raw INSERT statements. Sibling of
 * RealmFixture; timestamps are UTC 'Y-m-d H:i:s' (same format the app writes),
 * and the optional *_age arguments make it easy to seed rows the maintenance
 * TTL checks consider expired.
 */
final class AuthRecordFixture
{
    public static function createUser(
        PDO $pdo,
        string $realmId,
        string $email,
        string $password = 'testpass',
        bool $valid = true,
        string $name = 'Test User',
    ): string {
        $id = getGuid();
        $pdo->prepare(
            "INSERT INTO users (id, realm_id, name, email, password, valid)
             VALUES (:id, :realm, :name, :email, :password, :valid)"
        )->execute([
            ':id' => $id,
            ':realm' => $realmId,
            ':name' => $name,
            ':email' => $email,
            ':password' => password_hash($password, PASSWORD_BCRYPT, ['cost' => 4]),
            ':valid' => $valid ? 1 : 0,
        ]);

        return $id;
    }

    public static function createSession(
        PDO $pdo,
        string $realmId,
        string $userId,
        string $status = 'ACTIVE',
        ?string $createdAtAge = null,
        ?string $updatedAtAge = null,
    ): string {
        $id = getGuid();
        $pdo->prepare(
            "INSERT INTO sessions (id, realm_id, user_id, acr, status, created_at, updated_at)
             VALUES (:id, :realm, :user, '0', :status, :created_at, :updated_at)"
        )->execute([
            ':id' => $id,
            ':realm' => $realmId,
            ':user' => $userId,
            ':status' => $status,
            ':created_at' => self::sqlTime($createdAtAge),
            ':updated_at' => $updatedAtAge === null ? null : self::sqlTime($updatedAtAge),
        ]);

        return $id;
    }

    public static function createLogin(
        PDO $pdo,
        string $clientId,
        ?string $sessionId = null,
        string $status = 'ACTIVE',
        string $redirectUri = 'https://example.com',
        ?string $createdAtAge = null,
        ?string $authenticatedAtAge = null,
    ): string {
        $id = getGuid();
        $createdAt = self::sqlTime($createdAtAge);

        $pdo->prepare(
            "INSERT INTO logins (id, client_id, session_id, state, nonce, scope, redirect_uri, response_mode, status, authenticated_at, created_at, updated_at)
             VALUES (:id, :client, :session, 'st', 'nc', 'openid', :redirect_uri, 'query', :status, :authenticated_at, :created_at, :updated_at)"
        )->execute([
            ':id' => $id,
            ':client' => $clientId,
            ':session' => $sessionId,
            ':redirect_uri' => $redirectUri,
            ':status' => $status,
            ':authenticated_at' => $authenticatedAtAge === null ? null : self::sqlTime($authenticatedAtAge),
            ':created_at' => $createdAt,
            ':updated_at' => $createdAt,
        ]);

        return $id;
    }

    public static function createOfflineSession(
        PDO $pdo,
        string $realmId,
        string $userId,
        string $clientId,
        string $status = 'ACTIVE',
        ?string $createdAtAge = null,
        ?string $updatedAtAge = null,
        ?string $nonce = 'nc',
        ?string $refreshToken = null,
    ): string {
        $id = getGuid();
        $pdo->prepare(
            "INSERT INTO offline_sessions (id, realm_id, user_id, client_id, acr, scope, nonce, refresh_token, status, created_at, updated_at)
             VALUES (:id, :realm, :user, :client, '0', 'openid offline_access', :nonce, :refresh, :status, :created_at, :updated_at)"
        )->execute([
            ':id' => $id,
            ':realm' => $realmId,
            ':user' => $userId,
            ':client' => $clientId,
            ':nonce' => $nonce,
            ':refresh' => $refreshToken ?? getGuid(),
            ':status' => $status,
            ':created_at' => self::sqlTime($createdAtAge),
            ':updated_at' => $updatedAtAge === null ? null : self::sqlTime($updatedAtAge),
        ]);

        return $id;
    }

    public static function createBlacklistEntry(PDO $pdo, string $jti, int $exp): void
    {
        $pdo->prepare('INSERT INTO token_blacklist (jti, exp) VALUES (:jti, :exp)')
            ->execute([':jti' => $jti, ':exp' => $exp]);
    }

    private static function sqlTime(?string $age): string
    {
        return $age === null ? gmdate('Y-m-d H:i:s') : gmdate('Y-m-d H:i:s', strtotime($age));
    }
}
