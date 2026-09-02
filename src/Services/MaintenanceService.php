<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Interfaces\LoginRepository;
use AuthServer\Interfaces\OfflineSessionRepository;
use AuthServer\Interfaces\SessionRepository;
use AuthServer\Repositories\TokenBlacklistRepository;

class MaintenanceService
{
    use RunsTransactions;

    public function __construct(
        private readonly \PDO $db,
        private readonly TokenBlacklistRepository $tokenBlacklistRepository,
        private readonly SessionRepository $sessionRepository,
        private readonly LoginRepository $loginRepository,
        private readonly OfflineSessionRepository $offlineSessionRepository,
    ) {
    }

    /**
     * @return array{blacklist_purged: int, logins_purged: int, sessions_purged: int, offline_sessions_purged: int}
     */
    public function cleanup(): array
    {
        return $this->transact(function (): array {
            $now = time();

            $blacklistPurged = $this->tokenBlacklistRepository->deleteExpired($now);
            $loginsPurged = $this->loginRepository->deleteExpired($now);
            $sessionsPurged = $this->sessionRepository->deleteExpired();
            $offlineSessionsPurged = $this->offlineSessionRepository->deleteExpired($now);

            return [
                'blacklist_purged' => $blacklistPurged,
                'logins_purged' => $loginsPurged,
                'sessions_purged' => $sessionsPurged,
                'offline_sessions_purged' => $offlineSessionsPurged,
            ];
        });
    }
}
