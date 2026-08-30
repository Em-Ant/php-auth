<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Interfaces\LoginRepository;
use AuthServer\Interfaces\OfflineSessionRepository;
use AuthServer\Interfaces\SessionRepository;

/**
 * Single home for the admin-side revocation rule: invalidating a session also
 * deletes its logins, and expiring offline refresh grants accompanies any
 * invalidation (offline tokens deliberately survive SSO logout and are only
 * admin-revocable through this path).
 *
 * Revocations are atomic: each public method runs in its own transaction, or
 * joins the caller's transaction when one is already active (SQLite has no
 * nested transactions, so the rotation path and this service share the same
 * PDO connection without double-wrapping).
 */
class SessionRevocationService
{
    use RunsTransactions;

    public function __construct(
        private readonly \PDO $db,
        private readonly SessionRepository $sessions,
        private readonly LoginRepository $logins,
        private readonly OfflineSessionRepository $offlineSessions,
    ) {
    }

    /**
     * Deletes the sessions (and their logins) of a user and/or client and
     * expires their offline refresh grants. Returns the invalidated count.
     */
    public function revokeFor(?string $userId, ?string $clientId): int
    {
        return $this->transact(function () use ($userId, $clientId): int {
            $count = $this->expireOfflineGrants($userId, $clientId);

            foreach ($this->sessionIdsToInvalidate($userId, $clientId) as $sessionId) {
                $this->revokeSession($sessionId);
                $count++;
            }

            return $count;
        });
    }

    /**
     * Deletes a single session and its logins (no offline grants involved).
     */
    public function revokeSession(string $sessionId): void
    {
        $this->transact(function () use ($sessionId): void {
            $this->logins->deleteBySessionId($sessionId);
            $this->sessions->delete($sessionId);
        });
    }

    private function expireOfflineGrants(?string $userId, ?string $clientId): int
    {
        $count = 0;
        if ($userId !== null) {
            $count += $this->offlineSessions->setExpiredByUserId($userId);
        }
        if ($clientId !== null) {
            $count += $this->offlineSessions->setExpiredByClientId($clientId);
        }
        return $count;
    }

    /**
     * @return list<string>
     */
    private function sessionIdsToInvalidate(?string $userId, ?string $clientId): array
    {
        $sessionIds = [];
        if ($userId !== null) {
            foreach ($this->sessions->findAll(null, $userId) as $session) {
                $sessionIds[] = $session->getId();
            }
        }
        if ($clientId !== null) {
            foreach ($this->logins->findAll(null, $clientId) as $login) {
                if ($login->getSessionId() !== null) {
                    $sessionIds[] = $login->getSessionId();
                }
            }
        }
        return array_values(array_unique($sessionIds));
    }
}
