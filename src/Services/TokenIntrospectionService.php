<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\AuthenticationFailed;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\LoginRepository as ILoginRepo;
use AuthServer\Interfaces\OfflineSessionRepository as IOfflineSessionRepo;
use AuthServer\Models\LoginStatus;
use AuthServer\Models\OfflineSessionStatus;
use AuthServer\Models\Realm;
use Psr\Log\LoggerInterface;

class TokenIntrospectionService
{
    private ILoginRepo $loginRepository;
    private IOfflineSessionRepo $offlineSessionRepository;
    private ClientAuthenticator $clientAuthenticator;
    private TokenValidator $tokenValidator;
    private LoggerInterface $logger;

    public function __construct(
        ILoginRepo $loginRepo,
        IOfflineSessionRepo $offlineSessionRepo,
        ClientAuthenticator $clientAuthenticator,
        TokenValidator $tokenValidator,
        LoggerInterface $logger
    ) {
        $this->loginRepository = $loginRepo;
        $this->offlineSessionRepository = $offlineSessionRepo;
        $this->clientAuthenticator = $clientAuthenticator;
        $this->tokenValidator = $tokenValidator;
        $this->logger = $logger;
    }

    public function introspect(array $params, Realm $realm): array
    {
        $token = $params['token'] ?? '';
        if ($token === '') {
            $this->logger->info('introspect: token parameter missing');
            throw new ValidationFailed('missing required parameter (token)');
        }

        $clientId = $params['client_id'] ?? '';
        $this->validateIntrospectClient($clientId, $params);

        $claims = $this->tokenValidator->validate($token, $realm);
        if ($claims === null) {
            return ['active' => false];
        }

        return match ($claims['typ'] ?? '') {
            'Refresh' => $this->introspectRefreshToken($token, $claims, $realm),
            'Offline' => $this->introspectOfflineToken($token, $claims, $realm),
            default => $this->introspectAccessToken($claims),
        };
    }

    private function validateIntrospectClient(string $clientId, array $params): void
    {
        $client = $this->clientAuthenticator->authenticate($clientId, $params);
        if ($client === null) {
            $this->logger->info("introspect: client $clientId authentication failed");
            throw new AuthenticationFailed('invalid client');
        }
    }

    private function introspectRefreshToken(string $token, array $decoded, Realm $realm): array
    {
        $login = $this->loginRepository->findByRefreshToken($token, $realm->getId());
        if ($login === null || $login->getStatus() !== LoginStatus::Active) {
            return ['active' => false];
        }

        return $this->introspectActiveRefreshToken(
            $decoded,
            $login->getClientId(),
            $login->getScope()
        );
    }

    private function introspectOfflineToken(string $token, array $decoded, Realm $realm): array
    {
        $offline = $this->offlineSessionRepository->findByRefreshToken(
            $token,
            $realm->getId()
        );
        if ($offline === null || $offline->getStatus() !== OfflineSessionStatus::Active) {
            return ['active' => false];
        }

        return $this->introspectActiveRefreshToken(
            $decoded,
            $offline->getClientId(),
            $offline->getScope()
        );
    }

    private function introspectActiveRefreshToken(
        array $decoded,
        string $clientId,
        string $scope
    ): array {
        return [
            'active' => true,
            'sub' => $decoded['sub'] ?? '',
            'aud' => $decoded['aud'] ?? '',
            'iss' => $decoded['iss'] ?? '',
            'exp' => $decoded['exp'] ?? 0,
            'iat' => $decoded['iat'] ?? 0,
            'jti' => $decoded['jti'] ?? '',
            'token_type' => 'refresh_token',
            'client_id' => $clientId,
            'scope' => $scope,
            'sid' => $decoded['sid'] ?? '',
        ];
    }

    private function introspectAccessToken(array $decoded): array
    {
        $exp = $decoded['exp'] ?? 0;
        $jti = $decoded['jti'] ?? '';
        $typ = $decoded['typ'] ?? 'Bearer';

        return [
            'active' => true,
            'sub' => $decoded['sub'] ?? '',
            'aud' => $decoded['aud'] ?? '',
            'iss' => $decoded['iss'] ?? '',
            'exp' => $exp,
            'iat' => $decoded['iat'] ?? 0,
            'jti' => $jti,
            'token_type' => $typ,
            'client_id' => $decoded['azp'] ?? $decoded['aud'] ?? '',
            'scope' => $decoded['scope'] ?? '',
            'sid' => $decoded['sid'] ?? '',
        ];
    }
}
