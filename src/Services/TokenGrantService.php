<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\StorageFailed;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\LoginRepository as ILoginRepo;
use AuthServer\Interfaces\SessionRepository as ISessionRepo;
use AuthServer\Interfaces\UserRepository as IUserRepo;
use AuthServer\Models\Client;
use AuthServer\Models\GrantType;
use AuthServer\Models\LoginEvent;
use AuthServer\Models\LoginStatus;
use AuthServer\Models\Realm;
use AuthServer\Models\SessionStatus;
use Psr\Log\LoggerInterface;

class TokenGrantService
{
    private SessionOrchestrator $sessionOrchestrator;
    private ISessionRepo $sessionRepository;
    private IUserRepo $userRepository;
    private ILoginRepo $loginRepository;
    private LoginStateMachine $loginStateMachine;
    private ClientAuthenticator $clientAuthenticator;
    private TokenService $tokenService;
    private TokenValidator $tokenValidator;
    private ScopeResolver $scopeResolver;
    private LoggerInterface $logger;

    public function __construct(
        SessionOrchestrator $sessionOrchestrator,
        ISessionRepo $sessionRepo,
        IUserRepo $userRepo,
        ILoginRepo $loginRepo,
        LoginStateMachine $loginStateMachine,
        ClientAuthenticator $clientAuthenticator,
        TokenService $tokenService,
        TokenValidator $tokenValidator,
        ScopeResolver $scopeResolver,
        LoggerInterface $logger
    ) {
        $this->sessionOrchestrator = $sessionOrchestrator;
        $this->sessionRepository = $sessionRepo;
        $this->userRepository = $userRepo;
        $this->loginRepository = $loginRepo;
        $this->loginStateMachine = $loginStateMachine;
        $this->clientAuthenticator = $clientAuthenticator;
        $this->tokenService = $tokenService;
        $this->tokenValidator = $tokenValidator;
        $this->scopeResolver = $scopeResolver;
        $this->logger = $logger;
    }

    public function getTokens(array $params, Realm $realm): array
    {
        $this->logger->info("generating tokens...");

        InputValidator::validateTokenParams($params);

        $client_id = $params['client_id'];
        $grant_type = $params['grant_type'];
        $code = $params['code'] ?? '';
        $redirect_uri = $params['redirect_uri'] ?? '';
        $refresh_token = $params['refresh_token'] ?? '';
        $code_verifier = $params['code_verifier'] ?? null;

        $client = $this->clientAuthenticator->authenticate($client_id, $params);
        if ($client === null) {
            $this->logger->info(
                "client $client_id authentication failed while generating tokens"
            );
            throw new ValidationFailed('invalid client');
        }

        if ($grant_type === GrantType::AuthorizationCode->value) {
            InputValidator::validateRedirectUri($client, $redirect_uri);
            return $this->getTokensByCode(
                $code,
                $redirect_uri,
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
        string $redirect_uri,
        Realm $realm,
        Client $client,
        ?string $code_verifier
    ): array {
        $this->logger->info("generating tokens from authorization code $code");
        $login = $this->loginRepository->findByCode($code, $realm->getId());

        if ($login === null) {
            $this->logger->error("invalid authorization code");
            throw new ValidationFailed('invalid_grant');
        }

        if ($login->getClientId() !== $client->getId()) {
            $this->logger->error(
                "authorization code not bound to client {$client->getId()}"
            );
            throw new ValidationFailed('invalid_grant');
        }

        if ($login->getRedirectUri() !== $redirect_uri) {
            $this->logger->error("authorization code not bound to redirect_uri");
            throw new ValidationFailed('invalid_grant');
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
        $session = $this->sessionRepository->findById($session_id);
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

        $user = $this->userRepository->findById($session->getUserId());
        if ($user === null) {
            throw new StorageFailed('invalid session');
        }

        $token_bundle = $this->tokenService->createTokenBundle(
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

        $login = $this->loginRepository->findByRefreshToken($refresh_token, $realm->getId());
        if ($login === null) {
            $this->logger->error("invalid refresh token");
            throw new ValidationFailed('invalid refresh token');
        }
        if ($login->getClientId() !== $client->getId()) {
            $this->logger->error(
                "refresh token not bound to client {$client->getId()}"
            );
            throw new ValidationFailed('invalid refresh token');
        }
        if ($login->getStatus() !== LoginStatus::Active) {
            $this->logger->error("login is in invalid status");
            throw new ValidationFailed('login is expired');
        }

        $login = $this->loginStateMachine->transition($login, LoginEvent::CheckExpiry, $realm);

        $valid = $this->tokenValidator->validate($refresh_token, $realm, 'Refresh');
        if ($valid === null) {
            $this->logger->error("refresh token failed validation");
            throw new ValidationFailed('refresh_token is expired');
        }

        $session_id = $login->getSessionId();
        if ($session_id === null) {
            throw new StorageFailed('invalid session');
        }
        $session = $this->sessionRepository->findById($session_id);
        if ($session === null) {
            throw new StorageFailed("invalid session $session_id");
        }
        if ($session->getStatus() !== SessionStatus::Active) {
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

        $user = $this->userRepository->findById($session->getUserId());
        if ($user === null) {
            $this->logger->error("invalid user for active session $session_id");
            throw new StorageFailed('invalid session');
        }

        $token_bundle = $this->tokenService->createTokenBundle(
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

    private function getClientCredentialsTokens(
        Realm $realm,
        Client $client,
        string $scope
    ): array {
        $this->logger->info(
            "generating tokens via client_credentials grant for {$client->getName()}"
        );

        $granted_scope = $this->scopeResolver->resolve(
            $scope === '' ? null : $scope,
            $client,
            $realm,
            false
        );

        return $this->tokenService->createClientCredentialsToken(
            $realm,
            $client,
            $granted_scope
        );
    }
}
