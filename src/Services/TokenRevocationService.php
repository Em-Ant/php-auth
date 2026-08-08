<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Interfaces\LoginRepository as ILoginRepo;
use AuthServer\Interfaces\SessionRepository as ISessionRepo;
use AuthServer\Models\LoginEvent;
use AuthServer\Models\Realm;
use AuthServer\Repositories\TokenBlacklistRepository;
use Psr\Log\LoggerInterface;

class TokenRevocationService
{
    private ILoginRepo $loginRepository;
    private ISessionRepo $sessionRepository;
    private LoginStateMachine $loginStateMachine;
    private ClientAuthenticator $clientAuthenticator;
    private TokenValidator $tokenValidator;
    private TokenBlacklistRepository $tokenBlacklistRepository;
    private LoggerInterface $logger;

    public function __construct(
        ILoginRepo $loginRepo,
        ISessionRepo $sessionRepo,
        LoginStateMachine $loginStateMachine,
        ClientAuthenticator $clientAuthenticator,
        TokenValidator $tokenValidator,
        TokenBlacklistRepository $tokenBlacklistRepository,
        LoggerInterface $logger
    ) {
        $this->loginRepository = $loginRepo;
        $this->sessionRepository = $sessionRepo;
        $this->loginStateMachine = $loginStateMachine;
        $this->clientAuthenticator = $clientAuthenticator;
        $this->tokenValidator = $tokenValidator;
        $this->tokenBlacklistRepository = $tokenBlacklistRepository;
        $this->logger = $logger;
    }

    public function revoke(array $params, Realm $realm): void
    {
        $token = $params['token'] ?? '';
        $tokenTypeHint = $params['token_type_hint'] ?? '';
        $clientId = $params['client_id'] ?? '';

        $client = $this->clientAuthenticator->authenticate($clientId, $params);
        if ($client === null) {
            return;
        }

        // Refresh token path (default when no hint, or hint is refresh_token)
        if ($tokenTypeHint !== 'access_token') {
            $login = $this->loginRepository->findByRefreshToken($token);
            if ($login !== null && $login->getClientId() === $client->getId()) {
                $this->logger->info("revoke: expiring login {$login->getId()}");
                $this->loginStateMachine->transition($login, LoginEvent::Expire, $realm);
                $sessionId = $login->getSessionId();
                if ($sessionId !== null) {
                    $this->sessionRepository->setExpired($sessionId);
                }
                return;
            }
        }

        // Access token path
        $claims = $this->tokenValidator->validate(
            $token,
            $realm,
            'Bearer',
            $client->getName()
        );
        if ($claims === null) {
            return;
        }

        $jti = $claims['jti'] ?? '';
        $exp = $claims['exp'] ?? 0;
        if ($jti !== '') {
            $this->tokenBlacklistRepository->add($jti, $exp);
            $this->logger->info("revoke: blacklisted jti $jti");
        }
    }
}
