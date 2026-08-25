<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\ClientRepository;
use AuthServer\Models\Client;
use AuthServer\Models\Realm;
use Psr\Log\LoggerInterface;

/**
 * RP-Initiated Logout: expires the SSO session identified by an
 * id_token_hint and resolves a safe post_logout_redirect_uri.
 */
class LogoutService
{
    private TokenValidator $tokenValidator;
    private SessionOrchestrator $sessionOrchestrator;
    private ClientRepository $clientRepository;
    private LoggerInterface $logger;

    public function __construct(
        TokenValidator $tokenValidator,
        SessionOrchestrator $sessionOrchestrator,
        ClientRepository $clientRepository,
        LoggerInterface $logger
    ) {
        $this->tokenValidator = $tokenValidator;
        $this->sessionOrchestrator = $sessionOrchestrator;
        $this->clientRepository = $clientRepository;
        $this->logger = $logger;
    }

    public function logout(string $idToken, Realm $realm): bool
    {
        $this->logger->info("logging out for id token");
        $claims = $this->tokenValidator->validateIdTokenHint($idToken, $realm);
        if ($claims === null) {
            throw new ValidationFailed('invalid id_token');
        }

        $sessionId = $claims['sid'] ?? '';
        if ($sessionId === '') {
            throw new ValidationFailed('invalid id_token');
        }

        $this->logger->info("token contains session id $sessionId");

        $this->sessionOrchestrator->expire($sessionId);
        $this->logger->info("session $sessionId set to expired - logout ok");
        return true;
    }

    public function validateLogoutRedirectUri(
        string $idToken,
        string $postLogoutRedirectUri
    ): ?string {
        return $this->registeredUriOrNull(
            $this->clientFromTokenHint($idToken),
            $postLogoutRedirectUri
        );
    }

    /**
     * Resolves the client referenced by an id_token_hint's `azp`/`aud`
     * claim; null when the hint is undecodable or names no known client.
     */
    private function clientFromTokenHint(string $idToken): ?Client
    {
        $payload = $this->tokenValidator->decodeClaimsOnly($idToken);
        if ($payload === null) {
            return null;
        }

        $clientName = $payload['azp'] ?? $payload['aud'] ?? null;
        if (!is_string($clientName) || $clientName === '') {
            return null;
        }

        return $this->clientRepository->findByName($clientName);
    }

    /**
     * The requested post-logout target when it is registered for the
     * client; null otherwise (empty target included).
     */
    private function registeredUriOrNull(?Client $client, string $target): ?string
    {
        if ($client === null || trim($target) === '') {
            return null;
        }

        try {
            InputValidator::validateRedirectUri($client, $target);
        } catch (ValidationFailed) {
            return null;
        }

        return $target;
    }
}
