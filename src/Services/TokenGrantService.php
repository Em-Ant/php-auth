<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\StorageFailed;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\ClientRepository as IClientRepo;
use AuthServer\Interfaces\LoginRepository as ILoginRepo;
use AuthServer\Interfaces\SessionRepository as ISessionRepo;
use AuthServer\Interfaces\UserRepository as IUserRepo;
use AuthServer\Models\Client;
use AuthServer\Models\GrantType;
use AuthServer\Models\LoginEvent;
use AuthServer\Models\LoginStatus;
use AuthServer\Models\Realm;
use Psr\Log\LoggerInterface;

class TokenGrantService
{
    private SessionOrchestrator $sessionOrchestrator;
    private IClientRepo $client_repository;
    private ISessionRepo $session_repository;
    private IUserRepo $user_repository;
    private ILoginRepo $login_repository;
    private LoginStateMachine $loginStateMachine;
    private SecretsService $secrets_service;
    private TokenService $token_service;
    private LoggerInterface $logger;

    public function __construct(
        SessionOrchestrator $sessionOrchestrator,
        IClientRepo $client_repo,
        ISessionRepo $session_repo,
        IUserRepo $user_repo,
        ILoginRepo $login_repo,
        LoginStateMachine $loginStateMachine,
        SecretsService $secrets_service,
        TokenService $token_service,
        LoggerInterface $logger
    ) {
        $this->sessionOrchestrator = $sessionOrchestrator;
        $this->client_repository = $client_repo;
        $this->session_repository = $session_repo;
        $this->user_repository = $user_repo;
        $this->login_repository = $login_repo;
        $this->loginStateMachine = $loginStateMachine;
        $this->secrets_service = $secrets_service;
        $this->token_service = $token_service;
        $this->logger = $logger;
    }

    public function getTokens(array $params, Realm $realm): array
    {
        $this->logger->info("generating tokens...");

        InputValidator::validateTokenParams($params);

        $client_id = $params['client_id'];
        $client_secret = $params['client_secret'] ?? '';
        $grant_type = $params['grant_type'];
        $code = $params['code'] ?? '';
        $redirect_uri = $params['redirect_uri'] ?? '';
        $refresh_token = $params['refresh_token'] ?? '';
        $code_verifier = $params['code_verifier'] ?? null;

        $client = $this->client_repository->findByName($client_id);
        if ($client === null) {
            $this->logger->info(
                "client $client_id not found while generating tokens"
            );
            throw new ValidationFailed('invalid client');
        }

        if ($client->requiresAuth()) {
            $hashed_secret = $client->getClientSecret();
            $this->logger->info("$client_id requires secret validation");
            $this->validateClientSecret($hashed_secret, $client_secret);
        }

        if ($grant_type === GrantType::AuthorizationCode->value) {
            InputValidator::validateRedirectUri($client, $redirect_uri);
            return $this->getTokensByCode(
                $code,
                $realm,
                $client,
                $code_verifier
            );
        }

        if ($grant_type === GrantType::RefreshToken->value) {
            return $this->getTokensByRefreshToken(
                $refresh_token,
                $realm,
                $client
            );
        }

        if ($grant_type === GrantType::ClientCredentials->value) {
            $scope = $params['scope'] ?? '';
            return $this->getClientCredentialsTokens($realm, $client, $scope);
        }

        $this->logger->error("unsupported token flow $grant_type");
        throw new ValidationFailed('unsupported flow');
    }

    private function getTokensByCode(
        string $code,
        Realm $realm,
        Client $client,
        ?string $code_verifier
    ): array {
        $this->logger->info("generating tokens from authorization code $code");
        $login = $this->login_repository->findByCode($code);

        if ($login === null) {
            $this->logger->error("invalid authorization code");
            throw new ValidationFailed('invalid code');
        }

        $code_challenge = $login->getCodeChallenge();
        if ($code_verifier !== null || $code_challenge !== null) {
            InputValidator::validateCodeChallenge($code_challenge, $code_verifier);
        }
        if ($login->getStatus() !== LoginStatus::Authenticated) {
            $this->logger->error("code $code is expired");
            throw new ValidationFailed('code is expired');
        }

        $session_id = $login->getSessionId();
        if ($session_id === null) {
            throw new StorageFailed('invalid session');
        }
        $session = $this->session_repository->findById($session_id);
        if ($session === null) {
            throw new StorageFailed("invalid session $session_id");
        }

        $expiryCheck = $this->sessionOrchestrator->checkExpiry(
            $session,
            $realm->getSessionExpiresIn(),
            $realm->getIdleSessionExpiresIn()
        );
        if (!$expiryCheck) {
            $this->logger->error("session $session_id expired");
            throw new ValidationFailed('session expired');
        }

        $user = $this->user_repository->findById($session->getUserId());
        if ($user === null) {
            throw new StorageFailed('invalid session');
        }

        $token_bundle = $this->token_service->createTokenBundle(
            $realm,
            $session,
            $login,
            $client,
            $user
        );

        $this->loginStateMachine->transition(
            $login,
            LoginEvent::Activate,
            $realm,
            ['refresh_token' => $token_bundle['refresh_token']],
        );
        $this->sessionOrchestrator->refresh($session_id);

        return $token_bundle;
    }

    private function getTokensByRefreshToken(
        string $refresh_token,
        Realm $realm,
        Client $client
    ): array {
        $this->logger->info("generating tokens from refresh token");

        $login = $this->login_repository->findByrefreshToken($refresh_token);
        if ($login === null) {
            $this->logger->error("invalid refresh token");
            throw new ValidationFailed('invalid refresh token');
        }
        if ($login->getStatus() !== LoginStatus::Active) {
            $this->logger->error("login is in invalid status");
            throw new ValidationFailed('login is expired');
        }

        $login = $this->loginStateMachine->transition($login, LoginEvent::CheckExpiry, $realm);

        $expired = $this->token_service->tokenIsExpired($refresh_token);
        if ($expired) {
            $this->loginStateMachine->transition($login, LoginEvent::Expire, $realm);
            throw new ValidationFailed('refresh_token is expired');
        }

        $session_id = $login->getSessionId();
        if ($session_id === null) {
            throw new StorageFailed('invalid session');
        }
        $session = $this->session_repository->findById($session_id);
        if ($session === null) {
            throw new StorageFailed("invalid session $session_id");
        }
        if ($session->getStatus() !== 'ACTIVE') {
            $this->logger->error("invalid status for session $session_id - not active");
            throw new ValidationFailed('invalid session status');
        }

        $expiryCheck = $this->sessionOrchestrator->checkExpiry(
            $session,
            $realm->getSessionExpiresIn(),
            $realm->getIdleSessionExpiresIn()
        );
        if (!$expiryCheck) {
            $this->logger->error("session $session_id expired");
            throw new ValidationFailed('session expired');
        }

        $user = $this->user_repository->findById($session->getUserId());
        if ($user === null) {
            $this->logger->error("invalid user for active session $session_id");
            throw new StorageFailed('invalid session');
        }

        $token_bundle = $this->token_service->createTokenBundle(
            $realm,
            $session,
            $login,
            $client,
            $user
        );

        $this->loginStateMachine->transition(
            $login,
            LoginEvent::Refresh,
            $realm,
            ['refresh_token' => $token_bundle['refresh_token']],
        );
        $this->sessionOrchestrator->refresh($session_id);

        return $token_bundle;
    }

    private function validateClientSecret(
        string $hashed_secret,
        string $client_secret
    ): void {
        if (
            $client_secret === '' ||
            !$this->secrets_service->validatePassword(
                $client_secret,
                $hashed_secret
            )
        ) {
            throw new ValidationFailed('invalid client secret');
        }
    }

    private function getClientCredentialsTokens(
        Realm $realm,
        Client $client,
        string $scope
    ): array {
        $this->logger->info(
            "generating tokens via client_credentials grant for {$client->getName()}"
        );

        $requested_scope = $scope === '' ? implode(' ', $realm->getScope()) : $scope;
        $allowed_scope = $realm->getScope();

        foreach (explode(' ', $requested_scope) as $s) {
            if ($s !== '' && !in_array($s, $allowed_scope, true)) {
                throw new ValidationFailed('invalid scope');
            }
        }

        return $this->token_service->createClientCredentialsToken(
            $realm,
            $client,
            $requested_scope
        );
    }
}
