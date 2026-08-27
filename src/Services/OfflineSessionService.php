<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\OAuth2Error;
use AuthServer\Exceptions\StorageFailed;
use AuthServer\Interfaces\OfflineSessionRepository as IOfflineSessionRepo;
use AuthServer\Interfaces\UserRepository as IUserRepo;
use AuthServer\Models\Client;
use AuthServer\Models\Login;
use AuthServer\Models\OfflineSession;
use AuthServer\Models\OfflineSessionStatus;
use AuthServer\Models\Realm;
use AuthServer\Models\Session;
use AuthServer\Models\User;
use Psr\Log\LoggerInterface;

use function AuthServer\getGuid;

/**
 * Owns the offline_access lifecycle. Offline grants are per-client records in
 * offline_sessions, independent of the realm-wide SSO session: they carry
 * their own sid/acr/auth_time and survive SSO logout. No session checks here.
 */
class OfflineSessionService
{
    private IOfflineSessionRepo $offlineSessionRepository;
    private IUserRepo $userRepository;
    private TokenService $tokenService;
    private TokenValidator $tokenValidator;
    private LoggerInterface $logger;

    public function __construct(
        IOfflineSessionRepo $offlineSessionRepo,
        IUserRepo $userRepo,
        TokenService $tokenService,
        TokenValidator $tokenValidator,
        LoggerInterface $logger
    ) {
        $this->offlineSessionRepository = $offlineSessionRepo;
        $this->userRepository = $userRepo;
        $this->tokenService = $tokenService;
        $this->tokenValidator = $tokenValidator;
        $this->logger = $logger;
    }

    /**
     * Creates the offline session at auth-code exchange when the granted
     * scope includes offline_access, and returns the token bundle. The
     * `logins` row is left untouched: no refresh token, no activation, it
     * expires by its own short timers.
     */
    public function createOfflineGrant(
        Realm $realm,
        Login $login,
        Session $session,
        Client $client,
        User $user
    ): array {
        $offlineSession = new OfflineSession(
            getGuid(),
            $realm->getId(),
            $user->getId(),
            $client->getId(),
            $login->getScope(),
            null,
            $session->getAcr(),
            $login->getNonce(),
            $login->getAuthenticatedAt()?->format('Y-m-d H:i:s')
        );

        $bundle = $this->tokenService->createOfflineTokenBundle(
            $realm,
            $offlineSession,
            $client,
            $user,
            $session->getId()
        );

        $offlineSession->setRefreshToken($bundle['refresh_token']);
        $this->offlineSessionRepository->create($offlineSession);

        $this->logger->info(
            "offline session {$offlineSession->getId()} created for client {$client->getName()}"
        );

        return $bundle;
    }

    /**
     * Full offline refresh lifecycle: DB lookup, client binding, status and
     * sliding-TTL checks, token validation, rotation. The offline session is
     * the source of truth — the SSO session is never consulted.
     */
    public function refreshOfflineGrant(
        string $refreshToken,
        Realm $realm,
        Client $client
    ): array {
        $this->logger->info("refreshing offline grant for client {$client->getName()}");

        $offlineSession = $this->offlineSessionRepository->findByRefreshToken(
            $refreshToken,
            $realm->getId()
        );
        if ($offlineSession === null) {
            $this->logger->error("invalid offline refresh token");
            throw OAuth2Error::invalidGrant('invalid refresh token');
        }
        if ($offlineSession->getClientId() !== $client->getId()) {
            $this->logger->error(
                "offline refresh token not bound to client {$client->getId()}"
            );
            throw OAuth2Error::invalidGrant('invalid refresh token');
        }
        if (
            $offlineSession->getStatus() !== OfflineSessionStatus::Active
            || $this->isExpired($offlineSession, $realm)
        ) {
            $this->logger->error("offline session {$offlineSession->getId()} is expired");
            throw OAuth2Error::invalidGrant('offline session is expired');
        }

        $valid = $this->tokenValidator->validate($refreshToken, $realm, 'Offline');
        if ($valid === null) {
            $this->logger->error("offline refresh token failed validation");
            throw OAuth2Error::invalidGrant('refresh_token is expired');
        }

        $user = $this->userRepository->findById($offlineSession->getUserId());
        if ($user === null) {
            $this->logger->error(
                "invalid user for offline session {$offlineSession->getId()}"
            );
            throw new StorageFailed('invalid offline session');
        }

        $bundle = $this->tokenService->createOfflineTokenBundle(
            $realm,
            $offlineSession,
            $client,
            $user,
            $offlineSession->getId()
        );

        $ok = $this->offlineSessionRepository->refresh(
            $offlineSession->getId(),
            $bundle['refresh_token']
        );
        if (!$ok) {
            throw new StorageFailed('failed to persist refreshed offline session');
        }

        $this->logger->info("offline session {$offlineSession->getId()} refreshed");

        return $bundle;
    }

    private function isExpired(OfflineSession $offlineSession, Realm $realm): bool
    {
        $updatedAt = $offlineSession->getUpdatedAt() ?? $offlineSession->getCreatedAt();
        $now = new \DateTime();

        return (clone $updatedAt)->add(
            new \DateInterval('PT' . $realm->getOfflineRefreshTokenExpiresIn() . 'S')
        ) < $now;
    }
}
