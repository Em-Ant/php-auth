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
        string $session_id,
        int $session_expires_in,
        int $idle_session_expires_in
    ): ?Session {
        $session = $this->sessionRepository->findById($session_id);
        if ($session === null || $session->getStatus() !== SessionStatus::Active) {
            return null;
        }
        return $this->checkExpiry($session, $session_expires_in, $idle_session_expires_in)
            ? $session
            : null;
    }

    public function checkExpiry(
        Session $session,
        int $exp_in_s,
        int $idle_exp_in_s
    ): bool {
        $now = new DateTime('now', new \DateTimeZone('UTC'));
        $created_at = $session->getCreatedAt();

        $is_expired = (clone $created_at)->add(
            new \DateInterval("PT{$exp_in_s}S")
        ) < $now;

        $is_idle_for_too_long = (clone $created_at)->add(
            new \DateInterval("PT{$idle_exp_in_s}S")
        ) < $now;

        return !$is_expired && !$is_idle_for_too_long;
    }

    public function expire(string $session_id): void
    {
        $ok = $this->sessionRepository->setExpired($session_id);
        if (!$ok) {
            throw new StorageFailed("unable to set session $session_id to expired");
        }
    }

    public function create(string $realm_id, string $user_id): Session
    {
        $session = $this->sessionRepository->create($realm_id, $user_id, '0');
        if ($session === null) {
            throw new StorageFailed('unable to create session');
        }
        return $session;
    }

    public function refresh(string $session_id): void
    {
        $ok = $this->sessionRepository->refresh($session_id);
        if (!$ok) {
            throw new StorageFailed("error refreshing session $session_id");
        }
    }
}
