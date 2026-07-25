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

class AuthenticationOrchestrator
{
    private SessionOrchestrator $sessionOrchestrator;
    private IClientRepo $client_repository;
    private IUserRepo $user_repository;
    private ILoginRepo $login_repository;
    private LoginStateMachine $loginStateMachine;
    private SecretsService $secrets_service;
    private TokenService $token_service;
    private LoggerInterface $logger;

    public function __construct(
        SessionOrchestrator $sessionOrchestrator,
        IClientRepo $client_repo,
        IUserRepo $user_repo,
        ILoginRepo $login_repo,
        LoginStateMachine $loginStateMachine,
        SecretsService $secrets_service,
        TokenService $token_service,
        LoggerInterface $logger
    ) {
        $this->sessionOrchestrator = $sessionOrchestrator;
        $this->client_repository = $client_repo;
        $this->user_repository = $user_repo;
        $this->login_repository = $login_repo;
        $this->loginStateMachine = $loginStateMachine;
        $this->secrets_service = $secrets_service;
        $this->token_service = $token_service;
        $this->logger = $logger;
    }

    public function validateRequiredLoginScope(
        array $realm_allowed_scope,
        string $required_scope
    ): void {
        if (!InputValidator::validateScope($realm_allowed_scope, $required_scope)) {
            $this->logger->info(
                "scope '$required_scope' not allowed for realm"
            );
            throw new ValidationFailed('scope not allowed for realm');
        }
    }

    public function initializeLogin(
        string $realm_id,
        array $query
    ): array {
        $client_name = $query['client_id'];
        $this->logger->info("initializing login for client $client_name");

        InputValidator::validateQueryParams($query);

        $client = $this->ensureValidClient($client_name, $realm_id, $query['redirect_uri']);

        $csrf_token = $this->secrets_service->generateCode();

        $login = $this->login_repository->createPending(
            $client->getId(),
            $query['state'],
            $query['nonce'],
            $query['scope'],
            $query['redirect_uri'],
            $query['response_mode'],
            $query['code_challenge'] ?? null,
            $csrf_token
        );

        if ($login === null) {
            $msg = "unable to create pending login for $client_name";
            $this->logger->error($msg);
            throw new StorageFailed($msg);
        }

        $login_id = $login->getId();
        $this->logger->info("pending login $login_id created");

        return [
            'login_id' => $login_id,
            'csrf_token' => $csrf_token,
        ];
    }

    public function validateCsrfToken(string $login_id, string $csrf_token): void
    {
        $login = $this->login_repository->findById($login_id);
        if ($login === null || $login->getCsrfToken() !== $csrf_token) {
            $this->logger->info("CSRF validation failed for login $login_id");
            throw new ValidationFailed('CSRF validation failed');
        }
    }

    public function createAuthorizedLogin(
        Session $session,
        Realm $realm,
        array $query
    ): Login {
        $client_name = $query['client_id'];
        $this->logger->info("initializing login for client $client_name");

        InputValidator::validateQueryParams($query);

        $client = $this->ensureValidClient($client_name, $realm->getId(), $query['redirect_uri']);

        $user_id = $session->getUserId();
        $user = $this->user_repository->findById($user_id);

        $session_id = $session->getId();
        if ($user === null) {
            throw new AuthenticationFailed(
                "invalid user $user_id for session $session_id"
            );
        }
        if (!InputValidator::validateScope($realm->getScope(), $query['scope'])) {
            throw new AuthenticationFailed('invalid realm scope');
        }

        $code = $this->secrets_service->generateCode();

        $login = $this->login_repository->createAuthenticated(
            $client->getId(),
            $session_id,
            $query['state'],
            $query['nonce'],
            $query['scope'],
            $query['redirect_uri'],
            $query['response_mode'],
            $code,
            $query['code_challenge'] ?? null
        );

        if ($login === null) {
            throw new StorageFailed(
                "unable to create authenticated login for session $session_id"
            );
        }

        $this->logger->info("authenticated login created");

        return $login;
    }

    public function ensureValidCredentials(
        string $realm_id,
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
        $user = $this->user_repository->findByEmailAndRealmId($email, $realm_id);
        if ($user === null) {
            $error = 'email not found';
        } else {
            $valid_pwd = $this->secrets_service->validatePassword(
                $password,
                $user->getPassword()
            );
            if (!$valid_pwd) {
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
        string $login_id,
        User $user,
        Realm $realm
    ): array {
        $this->logger->info("authenticating user for login $login_id");

        $login = $this->login_repository->findById($login_id);
        if (!$login) {
            throw new StorageFailed("unable to find login $login_id");
        }

        $scope = $login->getScope();
        if (!InputValidator::validateScope($realm->getScope(), $scope)) {
            throw new AuthenticationFailed('invalid user scope');
        }

        $session = $this->sessionOrchestrator->create(
            $realm->getId(),
            $user->getId()
        );

        $code = $this->secrets_service->generateCode();
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

    public function logout(string $id_token, Realm $realm): bool
    {
        $this->logger->info("logging out for id token");
        $token_valid = $this->token_service->validateToken($id_token, $realm);
        if (!$token_valid) {
            throw new ValidationFailed('invalid id_token');
        }
        $token_parsed = $this->token_service->decodeTokenPayload($id_token);
        $session_id = $token_parsed['sid'];

        $this->logger->info("token contains session id $session_id");

        $this->sessionOrchestrator->expire($session_id);
        $this->logger->info("session $session_id set to expired - logout ok");
        return true;
    }

    public function getClientUri(string $client_id): string
    {
        $this->logger->info("getting uri for client $client_id to enable cors on origin");
        $client = $this->client_repository->findByName($client_id);
        if ($client === null) {
            $this->logger->error("client $client_id not found");
            throw new ValidationFailed('invalid client_id');
        }
        return $client->getUri();
    }

    public function parseValidToken(string $token, Realm $realm): array
    {
        $is_valid = $this->token_service->validateToken($token, $realm);
        $is_expired = $this->token_service->tokenIsExpired($token);
        if (!$is_valid) {
            $this->logger->error("invalid token");
            throw new ValidationFailed('Token verification failed');
        }
        if ($is_expired) {
            $this->logger->error("token expired");
            throw new ValidationFailed('Token is expired');
        }

        return $this->token_service->decodeTokenPayload($token);
    }

    private function ensureValidClient(
        string $client_name,
        string $realm_id,
        string $redirect_uri
    ): Client {
        $client = $this->client_repository->findByName($client_name);
        if ($client === null) {
            $this->logger->error("client matching $client_name not found for realm");
            throw new ValidationFailed('invalid client id');
        }
        if ($client->getRealmId() !== $realm_id) {
            $this->logger->error("client $client_name realm id {$client->getRealmId()} doesn't match $realm_id");
            throw new ValidationFailed("invalid client for realm $realm_id");
        }
        InputValidator::validateRedirectUri($client, $redirect_uri);

        return $client;
    }
}
