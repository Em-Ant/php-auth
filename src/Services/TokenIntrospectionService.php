<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\AuthenticationFailed;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\ClientRepository as IClientRepo;
use AuthServer\Interfaces\LoginRepository as ILoginRepo;
use AuthServer\Models\LoginStatus;
use AuthServer\Models\Realm;
use AuthServer\Repositories\TokenBlacklistRepository;
use Psr\Log\LoggerInterface;

class TokenIntrospectionService
{
    private IClientRepo $client_repository;
    private ILoginRepo $login_repository;
    private SecretsService $secrets_service;
    private TokenService $token_service;
    private TokenBlacklistRepository $tokenBlacklistRepository;
    private LoggerInterface $logger;

    public function __construct(
        IClientRepo $client_repo,
        ILoginRepo $login_repo,
        SecretsService $secrets_service,
        TokenService $token_service,
        TokenBlacklistRepository $tokenBlacklistRepository,
        LoggerInterface $logger
    ) {
        $this->client_repository = $client_repo;
        $this->login_repository = $login_repo;
        $this->secrets_service = $secrets_service;
        $this->token_service = $token_service;
        $this->tokenBlacklistRepository = $tokenBlacklistRepository;
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

        $decoded = $this->decodeTokenSafely($token);
        if ($decoded === null) {
            return ['active' => false];
        }

        $typ = $decoded['typ'] ?? '';

        if ($typ === 'Refresh') {
            return $this->introspectRefreshToken($token, $decoded, $realm);
        }

        return $this->introspectAccessToken($token, $decoded, $realm);
    }

    private function validateIntrospectClient(string $clientId, array $params): void
    {
        $client = $this->client_repository->findByName($clientId);
        if ($client === null) {
            $this->logger->info("introspect: client $clientId not found");
            throw new AuthenticationFailed('invalid client');
        }

        if ($client->requiresAuth()) {
            $clientSecret = $params['client_secret'] ?? '';
            $hashedSecret = $client->getClientSecret();
            if (
                $clientSecret === ''
                || !$this->secrets_service->validatePassword($clientSecret, $hashedSecret)
            ) {
                $this->logger->info("introspect: invalid client secret for $clientId");
                throw new AuthenticationFailed('invalid client');
            }
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

    private function introspectRefreshToken(string $token, array $decoded, Realm $realm): array
    {
        $login = $this->login_repository->findByrefreshToken($token);
        if ($login === null || $login->getStatus() !== LoginStatus::Active) {
            return ['active' => false];
        }

        $exp = $decoded['exp'] ?? 0;
        if ($exp < time()) {
            return ['active' => false];
        }

        return [
            'active' => true,
            'sub' => $decoded['sub'] ?? '',
            'aud' => $decoded['aud'] ?? '',
            'iss' => $decoded['iss'] ?? '',
            'exp' => $exp,
            'iat' => $decoded['iat'] ?? 0,
            'jti' => $decoded['jti'] ?? '',
            'token_type' => 'refresh_token',
            'client_id' => $login->getClientId(),
            'scope' => $login->getScope(),
            'sid' => $decoded['sid'] ?? '',
        ];
    }

    private function introspectAccessToken(string $token, array $decoded, Realm $realm): array
    {
        $isValid = $this->token_service->validateToken($token, $realm);
        if (!$isValid) {
            return ['active' => false];
        }

        $exp = $decoded['exp'] ?? 0;
        if ($exp < time()) {
            return ['active' => false];
        }

        $jti = $decoded['jti'] ?? '';
        if ($jti !== '' && $this->tokenBlacklistRepository->exists($jti)) {
            return ['active' => false];
        }

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
