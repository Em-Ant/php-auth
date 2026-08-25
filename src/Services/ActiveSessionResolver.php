<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\OAuth2Error;
use AuthServer\Exceptions\StorageFailed;
use AuthServer\Interfaces\SessionRepository as ISessionRepo;
use AuthServer\Interfaces\UserRepository as IUserRepo;
use AuthServer\Models\Login;
use AuthServer\Models\Realm;
use AuthServer\Models\Session;
use AuthServer\Models\User;
use Psr\Log\LoggerInterface;

/**
 * Resolves the session behind a login and the user behind that session,
 * rejecting logins without a live session.
 */
class ActiveSessionResolver
{
    public function __construct(
        private SessionOrchestrator $sessionOrchestrator,
        private ISessionRepo $sessionRepository,
        private IUserRepo $userRepository,
        private LoggerInterface $logger,
    ) {
    }

    public function requireSession(Login $login): Session
    {
        $sessionId = $login->getSessionId();
        if ($sessionId === null) {
            throw new StorageFailed('invalid session');
        }

        $session = $this->sessionRepository->findById($sessionId);
        if ($session === null) {
            throw new StorageFailed("invalid session $sessionId");
        }

        return $session;
    }

    public function requireActiveUser(Session $session, Realm $realm): User
    {
        $expiryCheck = $this->sessionOrchestrator->checkExpiry(
            $session,
            $realm->getSessionExpiresIn(),
            $realm->getIdleSessionExpiresIn()
        );
        if (!$expiryCheck) {
            $sessionId = $session->getId();
            $this->logger->error("session $sessionId expired");
            throw OAuth2Error::invalidGrant('session expired');
        }

        $user = $this->userRepository->findById($session->getUserId());
        if ($user === null) {
            $sessionId = $session->getId();
            $this->logger->error("invalid user for active session $sessionId");
            throw new StorageFailed('invalid session');
        }

        return $user;
    }

    public function refresh(string $sessionId): void
    {
        $this->sessionOrchestrator->refresh($sessionId);
    }
}
