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
    public function authenticate(string $client_id, array $params): ?Client
    {
        $client = $this->clientRepository->findByName($client_id);
        if ($client === null) {
            $this->logger->info("client $client_id not found");
            return null;
        }

        if ($client->requiresAuth()) {
            $client_secret = $params['client_secret'] ?? '';
            if (
                $client_secret === ''
                || !$this->secretsService->validatePassword(
                    $client_secret,
                    $client->getClientSecret()
                )
            ) {
                $this->logger->info("invalid client secret for $client_id");
                return null;
            }
        }

        return $client;
    }
}
