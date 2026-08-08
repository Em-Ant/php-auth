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
    private IClientRepo $clientRepository;
    private IUserRepo $userRepository;
    private ILoginRepo $loginRepository;
    private LoginStateMachine $loginStateMachine;
    private SecretsService $secretsService;
    private TokenService $tokenService;
    private ScopeResolver $scopeResolver;
    private LoggerInterface $logger;

    public function __construct(
        SessionOrchestrator $sessionOrchestrator,
        IClientRepo $clientRepo,
        IUserRepo $userRepo,
        ILoginRepo $loginRepo,
        LoginStateMachine $loginStateMachine,
        SecretsService $secretsService,
        TokenService $tokenService,
        ScopeResolver $scopeResolver,
        LoggerInterface $logger
    ) {
        $this->sessionOrchestrator = $sessionOrchestrator;
        $this->clientRepository = $clientRepo;
        $this->userRepository = $userRepo;
        $this->loginRepository = $loginRepo;
        $this->loginStateMachine = $loginStateMachine;
        $this->secretsService = $secretsService;
        $this->tokenService = $tokenService;
        $this->scopeResolver = $scopeResolver;
        $this->logger = $logger;
    }

    public function validateRequiredLoginScope(
        Realm $realm,
        string $client_name,
        string $required_scope
    ): void {
        $client = $this->clientRepository->findByName($client_name);
        if ($client === null) {
            throw new ValidationFailed('invalid client id');
        }
        $this->scopeResolver->resolve($required_scope, $client, $realm, true);
    }

    public function initializeLogin(
        string $realm_id,
        array $query
    ): array {
        $client_name = $query['client_id'];
        $this->logger->info("initializing login for client $client_name");

        InputValidator::validateQueryParams($query);

        $client = $this->ensureValidClient($client_name, $realm_id, $query['redirect_uri']);

        $csrf_token = $this->secretsService->generateCode();

        $login = $this->loginRepository->createPending(
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
        $login = $this->loginRepository->findById($login_id);
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
        $this->logger->info("creating authorized login for client $client_name");

        InputValidator::validateQueryParams($query);

        $client = $this->ensureValidClient($client_name, $realm->getId(), $query['redirect_uri']);

        $user_id = $session->getUserId();
        $user = $this->userRepository->findById($user_id);

        $session_id = $session->getId();
        if ($user === null) {
            throw new AuthenticationFailed(
                "invalid user $user_id for session $session_id"
            );
        }
        $this->scopeResolver->resolve($query['scope'], $client, $realm, true);

        $code = $this->secretsService->generateCode();

        $login = $this->loginRepository->createAuthenticated(
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
        $user = $this->userRepository->findByEmailAndRealmId($email, $realm_id);
        if ($user === null) {
            $error = 'email not found';
        } else {
            $valid_pwd = $this->secretsService->validatePassword(
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

        $login = $this->loginRepository->findById($login_id);
        if (!$login) {
            throw new StorageFailed("unable to find login $login_id");
        }

        $scope = $login->getScope();
        $client = $this->clientRepository->findById($login->getClientId());
        if ($client === null) {
            throw new StorageFailed("invalid client for login $login_id");
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

    public function logout(string $id_token, Realm $realm): bool
    {
        $this->logger->info("logging out for id token");
        $token_valid = $this->tokenService->validateToken($id_token, $realm);
        if (!$token_valid) {
            throw new ValidationFailed('invalid id_token');
        }
        $token_parsed = $this->tokenService->decodeTokenPayload($id_token);
        $session_id = $token_parsed['sid'];

        $this->logger->info("token contains session id $session_id");

        $this->sessionOrchestrator->expire($session_id);
        $this->logger->info("session $session_id set to expired - logout ok");
        return true;
    }

    public function getClientUri(string $client_id): string
    {
        $this->logger->info("getting uri for client $client_id to enable cors on origin");
        $client = $this->clientRepository->findByName($client_id);
        if ($client === null) {
            $this->logger->error("client $client_id not found");
            throw new ValidationFailed('invalid client_id');
        }
        return $client->getUri();
    }

    public function parseValidToken(string $token, Realm $realm): array
    {
        $is_valid = $this->tokenService->validateToken($token, $realm);
        $is_expired = $this->tokenService->tokenIsExpired($token);
        if (!$is_valid) {
            $this->logger->error("invalid token");
            throw new ValidationFailed('Token verification failed');
        }
        if ($is_expired) {
            $this->logger->error("token expired");
            throw new ValidationFailed('Token is expired');
        }

        return $this->tokenService->decodeTokenPayload($token);
    }

    public function validateLogoutRedirectUri(
        string $id_token,
        string $post_logout_redirect_uri
    ): ?string {
        if (trim($post_logout_redirect_uri) === '') {
            return null;
        }

        $payload = $this->tokenService->decodeTokenSafely($id_token);
        if ($payload === null) {
            return null;
        }

        $client_name = $payload['azp'] ?? $payload['aud'] ?? null;
        if (!is_string($client_name) || $client_name === '') {
            return null;
        }

        $client = $this->clientRepository->findByName($client_name);
        if ($client === null) {
            return null;
        }

        try {
            InputValidator::validateRedirectUri($client, $post_logout_redirect_uri);
        } catch (ValidationFailed) {
            return null;
        }

        return $post_logout_redirect_uri;
    }

    public function ensureValidClient(
        string $client_name,
        string $realm_id,
        string $redirect_uri
    ): Client {
        $client = $this->clientRepository->findByName($client_name);
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
