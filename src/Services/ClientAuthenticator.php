<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Interfaces\ClientRepository;
use AuthServer\Models\Client;
use Psr\Log\LoggerInterface;

class ClientAuthenticator
{
    private ClientRepository $clientRepository;
    private SecretsService $secretsService;
    private LoggerInterface $logger;

    public function __construct(
        ClientRepository $clientRepository,
        SecretsService $secretsService,
        LoggerInterface $logger
    ) {
        $this->clientRepository = $clientRepository;
        $this->secretsService = $secretsService;
        $this->logger = $logger;
    }

    /**
     * Resolves and authenticates a client. Returns null when the client is
     * unknown or its secret (if required) does not match — callers decide
     * how to translate a failed authentication.
     */
    public function authenticate(string $clientId, array $params): ?Client
    {
        $client = $this->clientRepository->findByName($clientId);
        if ($client === null) {
            $this->logger->info("client $clientId not found");
            return null;
        }

        if ($client->requiresAuth()) {
            $clientSecret = $params['client_secret'] ?? '';
            if (
                $clientSecret === ''
                || !$this->secretsService->validatePassword(
                    $clientSecret,
                    $client->getClientSecret()
                )
            ) {
                $this->logger->info("invalid client secret for $clientId");
                return null;
            }
        }

        return $client;
    }
}
