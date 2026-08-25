<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\StorageFailed;
use AuthServer\Interfaces\SessionRepository;
use AuthServer\Models\Session;
use AuthServer\Models\SessionStatus;
use DateTime;

class SessionOrchestrator
{
    private SessionRepository $sessionRepository;

    public function __construct(SessionRepository $sessionRepository)
    {
        $this->sessionRepository = $sessionRepository;
    }

    public function ensureValidSession(
        string $sessionId,
        int $sessionExpiresIn,
        int $idleSessionExpiresIn
    ): ?Session {
        $session = $this->sessionRepository->findById($sessionId);
        if ($session === null || $session->getStatus() !== SessionStatus::Active) {
            return null;
        }
        return $this->checkExpiry($session, $sessionExpiresIn, $idleSessionExpiresIn)
            ? $session
            : null;
    }

    public function checkExpiry(
        Session $session,
        int $expiresIn,
        int $idleExpiresIn
    ): bool {
        $now = new DateTime('now', new \DateTimeZone('UTC'));
        $createdAt = $session->getCreatedAt();

        $isExpired = (clone $createdAt)->add(
            new \DateInterval("PT{$expiresIn}S")
        ) < $now;

        $isIdleForTooLong = (clone $createdAt)->add(
            new \DateInterval("PT{$idleExpiresIn}S")
        ) < $now;

        return !$isExpired && !$isIdleForTooLong;
    }

    public function expire(string $sessionId): void
    {
        $ok = $this->sessionRepository->setExpired($sessionId);
        if (!$ok) {
            throw new StorageFailed("unable to set session $sessionId to expired");
        }
    }

    public function create(string $realmId, string $userId): Session
    {
        $session = $this->sessionRepository->create($realmId, $userId, '0');
        if ($session === null) {
            throw new StorageFailed('unable to create session');
        }
        return $session;
    }

    public function refresh(string $sessionId): void
    {
        $ok = $this->sessionRepository->refresh($sessionId);
        if (!$ok) {
            throw new StorageFailed("error refreshing session $sessionId");
        }
    }
}
