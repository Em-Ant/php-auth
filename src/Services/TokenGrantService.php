<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\OAuth2Error;
use AuthServer\Exceptions\StorageFailed;
use AuthServer\Interfaces\LoginRepository as ILoginRepo;
use AuthServer\Interfaces\SessionRepository as ISessionRepo;
use AuthServer\Interfaces\UserRepository as IUserRepo;
use AuthServer\Models\Client;
use AuthServer\Models\GrantType;
use AuthServer\Models\LoginEvent;
use AuthServer\Models\LoginStatus;
use AuthServer\Models\Realm;
use AuthServer\Models\Session;
use AuthServer\Models\SessionStatus;
use AuthServer\Models\User;
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
    private OfflineSessionService $offlineSessionService;
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
        OfflineSessionService $offlineSessionService,
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
        $this->offlineSessionService = $offlineSessionService;
        $this->logger = $logger;
    }

    public function getTokens(array $params, Realm $realm): array
    {
        $this->logger->info("generating tokens...");

        InputValidator::validateTokenParams($params);

        $clientId = $params['client_id'];
        $grantType = $params['grant_type'];
        $code = $params['code'] ?? '';
        $redirectUri = $params['redirect_uri'] ?? '';
        $refreshToken = $params['refresh_token'] ?? '';
        $codeVerifier = $params['code_verifier'] ?? null;

        $client = $this->clientAuthenticator->authenticate($clientId, $params);
        if ($client === null) {
            $this->logger->info(
                "client $clientId authentication failed while generating tokens"
            );
            throw OAuth2Error::invalidClient('invalid client');
        }

        if ($grantType === GrantType::AuthorizationCode->value) {
            return $this->getTokensByCode(
                $code,
                $redirectUri,
                $realm,
                $client,
                $codeVerifier
            );
        }

        if ($grantType === GrantType::RefreshToken->value) {
            return $this->getTokensByRefreshToken(
                $refreshToken,
                $realm,
                $client
            );
        }

        if ($grantType === GrantType::ClientCredentials->value) {
            $scope = $params['scope'] ?? '';
            return $this->getClientCredentialsTokens($realm, $client, $scope);
        }

        $this->logger->error("unsupported token flow $grantType");
        throw OAuth2Error::unsupportedGrantType('unsupported flow');
    }

    private function getTokensByCode(
        string $code,
        string $redirectUri,
        Realm $realm,
        Client $client,
        ?string $codeVerifier
    ): array {
        $this->logger->info("generating tokens from authorization code $code");
        $login = $this->loginRepository->findByCode($code, $realm->getId());

        if ($login === null) {
            $this->logger->error("invalid authorization code");
            throw OAuth2Error::invalidGrant('invalid_grant');
        }

        if ($login->getClientId() !== $client->getId()) {
            $this->logger->error(
                "authorization code not bound to client {$client->getId()}"
            );
            throw OAuth2Error::invalidGrant('invalid_grant');
        }

        if ($login->getRedirectUri() !== $redirectUri) {
            $this->logger->error("authorization code not bound to redirect_uri");
            throw OAuth2Error::invalidGrant('invalid_grant');
        }

        $codeChallenge = $login->getCodeChallenge();
        if ($codeVerifier !== null || $codeChallenge !== null) {
            InputValidator::validateCodeChallenge($codeChallenge, $codeVerifier);
        }
        if ($login->getStatus() !== LoginStatus::Authenticated) {
            $this->logger->error("code $code is expired");
            throw OAuth2Error::invalidGrant('code is expired');
        }

        $sessionId = $login->getSessionId();
        if ($sessionId === null) {
            throw new StorageFailed('invalid session');
        }
        $session = $this->sessionRepository->findById($sessionId);
        if ($session === null) {
            throw new StorageFailed("invalid session $sessionId");
        }

        $user = $this->activeSessionUser($session, $realm);

        if ($this->scopeHasOfflineAccess($login->getScope())) {
            return $this->offlineSessionService->createOfflineGrant(
                $realm,
                $login,
                $session,
                $client,
                $user
            );
        }

        $tokenBundle = $this->tokenService->createTokenBundle(
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
            ['refresh_token' => $tokenBundle['refresh_token']],
        );
        $this->sessionOrchestrator->refresh($sessionId);

        return $tokenBundle;
    }

    private function getTokensByRefreshToken(
        string $refreshToken,
        Realm $realm,
        Client $client
    ): array {
        $this->logger->info("generating tokens from refresh token");

        $claims = $this->tokenValidator->decodeClaimsOnly($refreshToken);
        if (($claims['typ'] ?? '') === 'Offline') {
            return $this->offlineSessionService->refreshOfflineGrant(
                $refreshToken,
                $realm,
                $client
            );
        }

        $login = $this->loginRepository->findByRefreshToken($refreshToken, $realm->getId());
        if ($login === null) {
            $this->logger->error("invalid refresh token");
            throw OAuth2Error::invalidGrant('invalid refresh token');
        }
        if ($login->getClientId() !== $client->getId()) {
            $this->logger->error(
                "refresh token not bound to client {$client->getId()}"
            );
            throw OAuth2Error::invalidGrant('invalid refresh token');
        }
        if ($login->getStatus() !== LoginStatus::Active) {
            $this->logger->error("login is in invalid status");
            throw OAuth2Error::invalidGrant('login is expired');
        }

        $login = $this->loginStateMachine->transition($login, LoginEvent::CheckExpiry, $realm);

        $valid = $this->tokenValidator->validate($refreshToken, $realm, 'Refresh');
        if ($valid === null) {
            $this->logger->error("refresh token failed validation");
            throw OAuth2Error::invalidGrant('refresh_token is expired');
        }

        $sessionId = $login->getSessionId();
        if ($sessionId === null) {
            throw new StorageFailed('invalid session');
        }
        $session = $this->sessionRepository->findById($sessionId);
        if ($session === null) {
            throw new StorageFailed("invalid session $sessionId");
        }
        if ($session->getStatus() !== SessionStatus::Active) {
            $this->logger->error("invalid status for session $sessionId - not active");
            throw OAuth2Error::invalidGrant('invalid session status');
        }

        $user = $this->activeSessionUser($session, $realm);

        $tokenBundle = $this->tokenService->createTokenBundle(
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
            ['refresh_token' => $tokenBundle['refresh_token']],
        );
        $this->sessionOrchestrator->refresh($sessionId);

        return $tokenBundle;
    }

    private function activeSessionUser(Session $session, Realm $realm): User
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

    private function scopeHasOfflineAccess(string $scope): bool
    {
        return in_array('offline_access', explode(' ', $scope), true);
    }

    private function getClientCredentialsTokens(
        Realm $realm,
        Client $client,
        string $scope
    ): array {
        $this->logger->info(
            "generating tokens via client_credentials grant for {$client->getName()}"
        );

        $grantedScope = $this->scopeResolver->resolve(
            $scope === '' ? null : $scope,
            $client,
            $realm,
            false
        );

        return $this->tokenService->createClientCredentialsToken(
            $realm,
            $client,
            $grantedScope
        );
    }
}
