<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\AuthenticationFailed;
use AuthServer\Exceptions\StorageFailed;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\ClientRepository as IClientRepo;
use AuthServer\Interfaces\LoginRepository as ILoginRepo;
use AuthServer\Interfaces\UserRepository as IUserRepo;
use AuthServer\Models\Client;
use AuthServer\Models\Login;
use AuthServer\Models\LoginEvent;
use AuthServer\Models\Realm;
use AuthServer\Models\Session;
use AuthServer\Models\User;
use Psr\Log\LoggerInterface;

/**
 * Drives the OIDC code-flow login lifecycle: client/redirect gating,
 * login initialization and CSRF validation, credential checks, and
 * login/session creation on authentication.
 */
class AuthenticationOrchestrator
{
    private const ERR_INVALID_CLIENT = 'invalid client id';

    private SessionOrchestrator $sessionOrchestrator;
    private IClientRepo $clientRepository;
    private IUserRepo $userRepository;
    private ILoginRepo $loginRepository;
    private LoginStateMachine $loginStateMachine;
    private SecretsService $secretsService;
    private ScopeResolver $scopeResolver;
    private LoggerInterface $logger;

    public function __construct(
        SessionOrchestrator $sessionOrchestrator,
        IClientRepo $clientRepo,
        IUserRepo $userRepo,
        ILoginRepo $loginRepo,
        LoginStateMachine $loginStateMachine,
        SecretsService $secretsService,
        ScopeResolver $scopeResolver,
        LoggerInterface $logger
    ) {
        $this->sessionOrchestrator = $sessionOrchestrator;
        $this->clientRepository = $clientRepo;
        $this->userRepository = $userRepo;
        $this->loginRepository = $loginRepo;
        $this->loginStateMachine = $loginStateMachine;
        $this->secretsService = $secretsService;
        $this->scopeResolver = $scopeResolver;
        $this->logger = $logger;
    }

    public function validateRequiredLoginScope(
        Realm $realm,
        string $clientName,
        string $requiredScope
    ): void {
        $client = $this->clientRepository->findByName($clientName);
        if ($client === null) {
            throw new ValidationFailed(self::ERR_INVALID_CLIENT);
        }
        $this->scopeResolver->resolve($requiredScope, $client, $realm, true);
    }

    public function initializeLogin(
        string $realmId,
        array $query
    ): array {
        InputValidator::validateQueryParams($query);

        $clientName = $query['client_id'];
        $this->logger->info("initializing login for client $clientName");

        $client = $this->ensureValidClient($clientName, $realmId, $query['redirect_uri']);

        $csrfToken = $this->secretsService->generateCode();

        $login = $this->loginRepository->createPending(
            ...$this->loginFields($query),
            client_id: $client->getId(),
            code_challenge: $query['code_challenge'] ?? null,
            csrf_token: $csrfToken
        );

        if ($login === null) {
            $msg = "unable to create pending login for $clientName";
            $this->logger->error($msg);
            throw new StorageFailed($msg);
        }

        $loginId = $login->getId();
        $this->logger->info("pending login $loginId created");

        return [
            'login_id' => $loginId,
            'csrf_token' => $csrfToken,
        ];
    }

    public function validateCsrfToken(string $loginId, string $csrfToken): void
    {
        $login = $this->loginRepository->findById($loginId);
        if ($login === null || !hash_equals($login->getCsrfToken(), $csrfToken)) {
            $this->logger->info("CSRF validation failed for login $loginId");
            throw new ValidationFailed('CSRF validation failed');
        }
    }

    public function createAuthorizedLogin(
        Session $session,
        Realm $realm,
        array $query
    ): Login {
        InputValidator::validateQueryParams($query);

        $clientName = $query['client_id'];
        $this->logger->info("creating authorized login for client $clientName");

        $client = $this->ensureValidClient($clientName, $realm->getId(), $query['redirect_uri']);

        $userId = $session->getUserId();
        $user = $this->userRepository->findById($userId);

        $sessionId = $session->getId();
        if ($user === null) {
            throw new AuthenticationFailed(
                "invalid user $userId for session $sessionId"
            );
        }
        $this->scopeResolver->resolve($query['scope'], $client, $realm, true);

        $code = $this->secretsService->generateCode();

        $login = $this->loginRepository->createAuthenticated(
            ...$this->loginFields($query),
            client_id: $client->getId(),
            session_id: $sessionId,
            code: $code,
            code_challenge: $query['code_challenge'] ?? null
        );

        if ($login === null) {
            throw new StorageFailed(
                "unable to create authenticated login for session $sessionId"
            );
        }

        $this->logger->info("authenticated login created");

        return $login;
    }

    public function ensureValidCredentials(
        string $realmId,
        string $email,
        string $password
    ): array {
        $this->logger->info("validating user credentials for $email");

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->logger->info("invalid email format for $email");
            return [
                'user' => null,
                'error' => 'invalid email',
            ];
        }

        $error = false;
        $user = $this->userRepository->findByEmailAndRealmId($email, $realmId);
        if ($user === null) {
            $error = 'email not found';
        } elseif (!$user->getValid()) {
            $error = 'user is disabled';
        } else {
            $validPwd = $this->secretsService->validatePassword(
                $password,
                $user->getPassword()
            );
            if (!$validPwd) {
                $error = 'invalid password';
            }
        }

        if ($error) {
            $this->logger->info("invalid credentials for $email");
            return [
                'user' => null,
                'error' => $error,
            ];
        }

        $this->logger->info("valid credentials for $email");
        return [
            'user' => $user,
            'error' => false,
        ];
    }

    public function authenticateLogin(
        string $loginId,
        User $user,
        Realm $realm
    ): array {
        $this->logger->info("authenticating user for login $loginId");

        $login = $this->loginRepository->findById($loginId);
        if (!$login) {
            throw new StorageFailed("unable to find login $loginId");
        }

        $scope = $login->getScope();
        $client = $this->clientRepository->findById($login->getClientId());
        if ($client === null) {
            throw new StorageFailed("invalid client for login $loginId");
        }
        $this->scopeResolver->resolve($scope, $client, $realm, true);

        $session = $this->sessionOrchestrator->create(
            $realm->getId(),
            $user->getId()
        );

        $code = $this->secretsService->generateCode();
        $this->loginStateMachine->transition(
            $login,
            LoginEvent::Authenticate,
            $realm,
            [
                'session_id' => $session->getId(),
                'code' => $code,
            ],
        );

        return [
            'login' => $login,
            'session' => $session,
        ];
    }

    public function getClientUri(string $clientId): string
    {
        $this->logger->info("getting uri for client $clientId to enable cors on origin");
        $client = $this->clientRepository->findByName($clientId);
        if ($client === null) {
            $this->logger->error("client $clientId not found");
            throw new ValidationFailed('invalid client_id');
        }

        // ACAO must be a serialized origin (scheme://host[:port]); for a
        // wildcard-registered client the full URI would be invalid CORS.
        $origin = InputValidator::originOf($client->getUri());
        if ($origin === null) {
            throw new ValidationFailed('invalid client uri');
        }

        return $origin;
    }

    /**
     * Gates the check-session iframe init: the requesting client must exist in
     * the realm and the reported origin must match the client's registered URI.
     */
    public function validateCheckSessionOrigin(
        Realm $realm,
        string $clientId,
        string $origin
    ): void {
        $client = $this->clientRepository->findByName($clientId);
        if ($client === null) {
            $this->logger->error("client $clientId not found for check-session init");
            throw new ValidationFailed(self::ERR_INVALID_CLIENT);
        }
        if ($client->getRealmId() !== $realm->getId()) {
            $this->logger->error("client $clientId not in realm {$realm->getName()}");
            throw new ValidationFailed('invalid client for realm');
        }

        InputValidator::validateClientOrigin($client, $origin);
    }

    /**
     * Creates the login row for the validated auth request, applying defaults
     * for the OIDC code-flow parameters that are optional (OIDC Core §3.1.2.1):
     * state, nonce, response_mode.
     */
    /**
     * OIDC code-flow fields shared by the pending and authenticated login rows
     * (OIDC Core §3.1.2.1). state, nonce and response_mode are optional for the
     * code flow, so defaults are applied when omitted.
     *
     * @return array{
     *     state: string,
     *     nonce: string,
     *     scope: string,
     *     redirect_uri: string,
     *     response_mode: string
     * }
     */
    private function loginFields(array $query): array
    {
        return [
            'state' => $query['state'] ?? '',
            'nonce' => $query['nonce'] ?? '',
            'scope' => $query['scope'],
            'redirect_uri' => $query['redirect_uri'],
            'response_mode' => $query['response_mode'] ?? 'query',
        ];
    }

    public function ensureValidClient(
        string $clientName,
        string $realmId,
        string $redirectUri
    ): Client {
        $client = $this->clientRepository->findByName($clientName);
        if ($client === null) {
            $this->logger->error("client matching $clientName not found for realm");
            throw new ValidationFailed(self::ERR_INVALID_CLIENT);
        }
        if ($client->getRealmId() !== $realmId) {
            $this->logger->error("client $clientName realm id {$client->getRealmId()} doesn't match $realmId");
            throw new ValidationFailed("invalid client for realm $realmId");
        }
        InputValidator::validateRedirectUri($client, $redirectUri);

        return $client;
    }
}
