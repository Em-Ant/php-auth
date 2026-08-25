<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\OAuth2Error;
use AuthServer\Models\Client;
use AuthServer\Models\GrantType;
use AuthServer\Models\LoginEvent;
use AuthServer\Models\LoginStatus;
use AuthServer\Models\Realm;
use AuthServer\Models\SessionStatus;
use Psr\Log\LoggerInterface;

class TokenGrantService
{
    private const ERR_INVALID_REFRESH_TOKEN = 'invalid refresh token';

    public function __construct(
        private ActiveSessionResolver $sessions,
        private LoginStateMachine $loginStateMachine,
        private ClientAuthenticator $clientAuthenticator,
        private TokenService $tokenService,
        private TokenValidator $tokenValidator,
        private OfflineSessionService $offlineSessionService,
        private LoggerInterface $logger,
    ) {
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
        $login = $this->loginStateMachine->findByCode($code, $realm->getId());

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

        $session = $this->sessions->requireSession($login);
        $sessionId = $session->getId();
        $user = $this->sessions->requireActiveUser($session, $realm);

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
        $this->sessions->refresh($sessionId);

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

        $login = $this->loginStateMachine->findByRefreshToken($refreshToken, $realm->getId());
        if ($login === null) {
            $this->logger->error(self::ERR_INVALID_REFRESH_TOKEN);
            throw OAuth2Error::invalidGrant(self::ERR_INVALID_REFRESH_TOKEN);
        }
        if ($login->getClientId() !== $client->getId()) {
            $this->logger->error(
                "refresh token not bound to client {$client->getId()}"
            );
            throw OAuth2Error::invalidGrant(self::ERR_INVALID_REFRESH_TOKEN);
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

        $session = $this->sessions->requireSession($login);
        $sessionId = $session->getId();
        if ($session->getStatus() !== SessionStatus::Active) {
            $this->logger->error("invalid status for session $sessionId - not active");
            throw OAuth2Error::invalidGrant('invalid session status');
        }

        $user = $this->sessions->requireActiveUser($session, $realm);

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
        $this->sessions->refresh($sessionId);

        return $tokenBundle;
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

        return $this->tokenService->createClientCredentialsToken(
            $realm,
            $client,
            $scope
        );
    }
}
