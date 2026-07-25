<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Interfaces\ClientRepository as IClientRepo;
use AuthServer\Interfaces\LoginRepository as ILoginRepo;
use AuthServer\Interfaces\SessionRepository as ISessionRepo;
use AuthServer\Models\LoginEvent;
use AuthServer\Models\Realm;
use AuthServer\Repositories\TokenBlacklistRepository;
use Psr\Log\LoggerInterface;

class TokenRevocationService
{
    private IClientRepo $client_repository;
    private ILoginRepo $login_repository;
    private ISessionRepo $session_repository;
    private LoginStateMachine $loginStateMachine;
    private SecretsService $secrets_service;
    private TokenService $token_service;
    private TokenBlacklistRepository $tokenBlacklistRepository;
    private LoggerInterface $logger;

    public function __construct(
        IClientRepo $client_repo,
        ILoginRepo $login_repo,
        ISessionRepo $session_repo,
        LoginStateMachine $loginStateMachine,
        SecretsService $secrets_service,
        TokenService $token_service,
        TokenBlacklistRepository $tokenBlacklistRepository,
        LoggerInterface $logger
    ) {
        $this->client_repository = $client_repo;
        $this->login_repository = $login_repo;
        $this->session_repository = $session_repo;
        $this->loginStateMachine = $loginStateMachine;
        $this->secrets_service = $secrets_service;
        $this->token_service = $token_service;
        $this->tokenBlacklistRepository = $tokenBlacklistRepository;
        $this->logger = $logger;
    }

    public function revoke(array $params, Realm $realm): void
    {
        $token = $params['token'] ?? '';
        $tokenTypeHint = $params['token_type_hint'] ?? '';
        $clientId = $params['client_id'] ?? '';

        $client = $this->client_repository->findByName($clientId);
        if ($client === null) {
            $this->logger->info("revoke: client $clientId not found");
            return;
        }

        if ($client->requiresAuth()) {
            $clientSecret = $params['client_secret'] ?? '';
            $hashedSecret = $client->getClientSecret();
            if (
                $clientSecret === ''
                || !$this->secrets_service->validatePassword($clientSecret, $hashedSecret)
            ) {
                $this->logger->info("revoke: invalid client secret for $clientId");
                return;
            }
        }

        // Refresh token path (default when no hint, or hint is refresh_token)
        if ($tokenTypeHint !== 'access_token') {
            $login = $this->login_repository->findByrefreshToken($token);
            if ($login !== null && $login->getClientId() === $client->getId()) {
                $this->logger->info("revoke: expiring login {$login->getId()}");
                $this->loginStateMachine->transition($login, LoginEvent::Expire, $realm);
                $sessionId = $login->getSessionId();
                if ($sessionId !== null) {
                    $this->session_repository->setExpired($sessionId);
                }
                return;
            }
        }

        // Access token path
        $decoded = $this->decodeTokenSafely($token);
        if ($decoded === null) {
            return;
        }

        $aud = $decoded['aud'] ?? $decoded['azp'] ?? '';
        if ((string) $aud !== $client->getName()) {
            $this->logger->info("revoke: token not issued to $clientId");
            return;
        }

        $isValid = $this->token_service->validateToken($token, $realm);
        if (!$isValid) {
            return;
        }

        $jti = $decoded['jti'] ?? '';
        $exp = $decoded['exp'] ?? 0;
        if ($jti !== '') {
            $this->tokenBlacklistRepository->add($jti, $exp);
            $this->logger->info("revoke: blacklisted jti $jti");
        }
    }

    private function decodeTokenSafely(string $token): ?array
    {
        try {
            $parts = explode('.', $token);
            if (count($parts) !== 3) {
                return null;
            }
            $payload = json_decode(\AuthServer\Services\Base64Utils::b64UrlDecode($parts[1]), true);
            return is_array($payload) ? $payload : null;
        } catch (\Throwable $e) {
            return null;
        }
    }
}
