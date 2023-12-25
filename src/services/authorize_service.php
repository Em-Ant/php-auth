<?php

namespace AuthServer\Services;

use AuthServer\Exceptions\InvalidInputException;
use AuthServer\Exceptions\StorageErrorException;
use AuthServer\Exceptions\CriticalLoginErrorException;
use AuthServer\Interfaces\ClientRepository as IClientRepo;
use AuthServer\Interfaces\SessionRepository as ISessionRepo;
use AuthServer\Interfaces\UserRepository as IUserRepo;
use AuthServer\Interfaces\LoginRepository as ILoginRepo;
use AuthServer\Interfaces\Logger;
use AuthServer\Models\Client;
use AuthServer\Models\Login;
use AuthServer\Models\Realm;
use AuthServer\Models\Session;
use AuthServer\Models\User;
use DateTime;
use AuthServer\Services\Base64Utils;

class AuthorizeService
{
    private IClientRepo $client_repository;
    private ISessionRepo $session_repository;
    private IUserRepo $user_repository;
    private ILoginRepo $login_repository;
    private SecretsService $secrets_service;
    private TokenService $token_service;
    private Logger $logger;

    public function __construct(
        IClientRepo $client_repo,
        ISessionRepo $session_repo,
        IUserRepo $user_repo,
        ILoginRepo $login_repo,
        SecretsService $secrets_service,
        TokenService $token_service,
        Logger $logger
    ) {
        $this->client_repository = $client_repo;
        $this->session_repository = $session_repo;
        $this->user_repository = $user_repo;
        $this->login_repository = $login_repo;
        $this->secrets_service = $secrets_service;
        $this->token_service = $token_service;
        $this->logger = $logger;
    }

    public function validateRequiredLoginScope(
        array $realm_allowed_scope,
        string $required_scope
    ) {
        if (!self::validateScope($realm_allowed_scope, $required_scope)) {
            $this->logger->info(
                "scope '$required_scope' not allowed for realm"
            );
            throw new InvalidInputException('scope not allowed for realm');
        }
    }

    public function initializeLogin(
        string $realm_id,
        array $query
    ): string {
        $client_name = $query['client_id'];
        $this->logger->info("initializing login for client $client_name");

        self::validateQueryParams($query);

        $client = $this->ensureValidClient($client_name, $realm_id, $query['redirect_uri']);

        $login = $this->login_repository->createPending(
            $client->getId(),
            $query['state'],
            $query['nonce'],
            $query['scope'],
            $query['redirect_uri'],
            $query['response_mode'],
            $query['code_challenge']
        );

        if ($login === null) {
            $msg = "unable to create pending login for $client_name";
            $this->logger->error($msg);
            throw new StorageErrorException($msg);
        }

        $login_id = $login->getId();
        $this->logger->info("pending login $login_id created");

        return $login->getId();
    }

    public function ensureValidSession(
        string $session_id,
        int $session_expires_in,
        int $idle_session_expires_in
    ): ?Session {
        $session = $this->session_repository->findById($session_id);
        if ($session == null || $session->getStatus() != 'ACTIVE') {
            return null;
        }
        $ok = $this->checkSessionValidity(
            $session,
            $session_expires_in,
            $idle_session_expires_in
        );
        return $ok ? $session : null;
    }

    public function createAuthorizedLogin(
        Session $session,
        Realm $realm,
        array $query
    ): Login {
        $client_name = $query['client_id'];
        $this->logger->info("initializing login for client $client_name");

        self::validateQueryParams($query);

        $client = $this->ensureValidClient($client_name, $realm->getId(), $query['redirect_uri']);

        $user_id = $session->getUserId();
        $user = $this->user_repository->findById($user_id);

        $session_id = $session->getId();
        if ($user == null) {
            throw new CriticalLoginErrorException(
                "invalid user $user_id for session $session_id "
            );
        }
        if (!self::validateScope($realm->getScope(), $query['scope'])) {
            throw new CriticalLoginErrorException('invalid realm scope');
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
            isset($query['code_challenge']) ? $query['code_challenge'] : null
        );

        if ($login === null) {
            throw new StorageErrorException(
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

        $error = false;
        $user = $this->user_repository->findByEmailAndRealmId($email, $realm_id);
        if ($user == null) {
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
                'error' => $error
            ];
        }

        $this->logger->info("valid credentials for $email");
        return [
            'user' => $user,
            'error' => false
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
            throw new StorageErrorException("unable to find login $login_id");
        }

        $this->checkLoginExpiration($login, $realm);

        $scope = $login->getScope();
        if (!self::validateScope($realm->getScope(), $scope)) {
            throw new CriticalLoginErrorException('invalid user scope');
        }

        $session = $this->session_repository->create(
            $realm->getId(),
            $user->getId(),
            '0'
        );

        if (!$session) {
            throw new StorageErrorException(
                "unable to create new session for login $login_id"
            );
        }

        $session_id = $session->getId();
        $code = $this->secrets_service->generateCode();
        $ok = $this->login_repository->setAuthenticated(
            $login_id,
            $session_id,
            $code
        );
        if (!$ok) {
            throw new StorageErrorException(
                "unable to authenticate login $login_id"
            );
        }

        $updated = $this->login_repository->findById($login_id);

        return [
            'login' => $updated,
            'session' => $session
        ];
    }

    public function getTokens(array $params, Realm $realm): array
    {
        $this->logger->info("generating tokens...");

        self::validateTokenParams($params);

        $client_id = $params['client_id'];
        $client_secret = $params['code'];
        $grant_type = $params['grant_type'];
        $code = $params['code'];
        $redirect_uri = $params['redirect_uri'];
        $refresh_token = $params['refresh_token'];
        $code_verifier = $params['code_verifier'] ?? null;

        $client = $this->client_repository->findByName($client_id);
        if ($client === null) {
            $this->logger->info(
                "client $client_id not found while generating tokens"
            );
            throw new InvalidInputException('invalid client');
        }

        if ($client->requiresAuth()) {
            $hashed_secret = $client->getClientSecret();
            $this->logger->info("$client_id requires secret validation");
            $this->validateClientSecret($hashed_secret, $client_secret ?: '');
        }


        switch ($grant_type) {
            case 'authorization_code':
                self::validateRedirectUri($client, $redirect_uri);
                return $this->getTokensByCode(
                    $code,
                    $realm,
                    $client,
                    $code_verifier
                );
            case 'refresh_token':
                return $this->getTokensByRefreshToken(
                    $refresh_token,
                    $realm,
                    $client
                );
            default:
                $this->logger->error("unsupported token flow $grant_type");
                throw new InvalidInputException('unsupported flow');
        }
    }

    public function logout(
        string $id_token,
        Realm $realm
    ): bool {
        $this->logger->info("logging out for id token");
        $token_valid = $this->token_service->validateToken($id_token, $realm);
        if (!$token_valid) {
            throw new InvalidInputException('invalid id_token');
        }
        $token_parsed = $this->token_service->decodeTokenPayload($id_token);
        $session_id = $token_parsed['sid'];

        $this->logger->info("token contains session id $session_id");

        $ok = $this->session_repository->setExpired($session_id);
        if (!$ok) {
            $this->logger->error("unable to transition $session_id to expired");
            throw new StorageErrorException('unable to update session');
        }
        $this->logger->info("session $session_id set to expired - logout ok");
        return $ok;
    }

    public function getClientUri(string $client_id)
    {
        $this->logger->info("getting uri for client $client_id to enable cors on origin");
        $client = $this->client_repository->findByName($client_id);
        if ($client === null) {
            $this->logger->error("client $client_id not found");
            throw new InvalidInputException('invalid client_id');
        }
        return $client->getUri();
    }

    public function parseValidToken(string $token, Realm $realm): array
    {
        $is_valid = $this->token_service->validateToken($token, $realm);
        $is_expired = $this->token_service->tokenIsExpired($token);
        if (!$is_valid) {
            $this->logger->error("invalid token");
            throw new InvalidInputException('Token verification failed');
        }
        if ($is_expired) {
            $this->logger->error("token expired");
            throw new InvalidInputException('Token is expired');
        }

        return $this->token_service->decodeTokenPayload($token);
    }

    private static function validateCodeChallenge(
        ?string $code_challenge,
        ?string $code_verifier,
    ) {
        if ($code_challenge !== Base64Utils::b64UrlEncode(hash('sha256', $code_verifier, true))) {
            throw new InvalidInputException('code_verifier does not match code_challenge');
        }
        return true;
    }

    private function getTokensByCode(
        string $code,
        Realm $realm,
        Client $client,
        ?string $code_verifier
    ): array {

        $this->logger->info("generating tokens from authorization code $code");
        $login = $this->login_repository->findByCode($code);

        $code_challenge = $login->getCodeChallenge();
        if ($code_verifier != null || $code_challenge != null) {
            self::validateCodeChallenge($code_challenge, $code_verifier);
        }

        if ($login === null) {
            $this->logger->error("invalid authorization code");
            throw new InvalidInputException('invalid code');
        }
        if ($login->getStatus() != 'AUTHENTICATED') {
            $this->logger->error("code $code is expired");
            throw new InvalidInputException('code is expired');
        }

        $this->checkLoginExpiration($login, $realm);

        $session_id = $login->getSessionId();
        $session = $this->session_repository->findById($session_id);
        if ($session == null) {
            throw new StorageErrorException("invalid session $session_id");
        }

        $ok = $this->checkSessionValidity(
            $session,
            $realm->getSessionExpiresIn(),
            $realm->getIdleSessionExpiresIn()
        );
        if (!$ok) {
            $this->logger->error("session $session_id expired");
            throw new InvalidInputException('session expired');
        }

        $user = $this->user_repository->findById($session->getUserId());
        if ($user == null) {
            throw new StorageErrorException('invalid session');
        }

        $token_bundle = $this->token_service->createTokenBundle(
            $realm,
            $session,
            $login,
            $client,
            $user
        );

        $login_id = $login->getId();
        $ok = $this->login_repository->setActive(
            $login_id,
            $token_bundle['refresh_token']
        );
        if (!$ok) {
            throw new StorageErrorException(
                "error setting login $login_id to active"
            );
        }
        $ok = $this->session_repository->refresh(
            $session_id
        );
        if (!$ok) {
            throw new StorageErrorException(
                "error refreshing session $session_id"
            );
        }

        return $token_bundle;
    }

    private function getTokensByRefreshToken(
        string $refresh_token,
        Realm $realm,
        Client $client
    ): array {
        $this->logger->info("generating tokens from refresh token");

        $login = $this->login_repository->findByrefreshToken($refresh_token);
        if ($login === null) {
            $this->logger->error("invalid refresh token");
            throw new InvalidInputException('invalid refresh token');
        }
        if ($login->getStatus() != 'ACTIVE') {
            $this->logger->error("login is in invalid status");
            throw new InvalidInputException('login is expired');
        }
        $login_id = $login->getId();

        $this->checkLoginExpiration($login, $realm);

        $expired = $this->token_service->tokenIsExpired($refresh_token);
        if ($expired) {
            $ok = $this->login_repository->setExpired($login_id);
            if (!$ok) {
                $this->logger->error("unable to set session $login_id to expired");
                throw new StorageErrorException('unable to set session to expired');
            }
            throw new InvalidInputException('refresh_token is expired');
        }

        $session_id = $login->getSessionId();
        $session = $this->session_repository->findById($session_id);
        if ($session == null) {
            throw new StorageErrorException("invalid session $session_id");
        }
        if ($session->getStatus() != 'ACTIVE') {
            $this->logger->error("invalid status for session $session_id - not active");
            throw new InvalidInputException('invalid session status');
        }


        $ok = $this->checkSessionValidity(
            $session,
            $realm->getSessionExpiresIn(),
            $realm->getIdleSessionExpiresIn()
        );
        if (!$ok) {
            $this->logger->error("session $session_id expired");
            throw new InvalidInputException('session expired');
        }

        $user = $this->user_repository->findById($session->getUserId());
        if ($user == null) {
            $this->logger->error("invalid user for active session $session_id");
            throw new StorageErrorException('invalid session');
        }

        $token_bundle = $this->token_service->createTokenBundle(
            $realm,
            $session,
            $login,
            $client,
            $user
        );

        $ok = $this->login_repository->refresh(
            $login_id,
            $token_bundle['refresh_token']
        );
        if (!$ok) {
            throw new StorageErrorException(
                "error refreshing login $login_id"
            );
        }
        $ok = $this->session_repository->refresh(
            $session_id
        );
        if (!$ok) {
            throw new StorageErrorException(
                "error refreshing session $session_id"
            );
        }

        return $token_bundle;
    }

    private function ensureValidClient(
        string $client_name,
        string $realm_id,
        string $redirect_uri
    ) {
        $client = $this->client_repository->findByName($client_name);
        if ($client === null) {
            $this->logger->error("client matching $client_name not found for realm");
            throw new InvalidInputException('invalid client id');
        }
        if ($client->getRealmId() !== $realm_id) {
            $this->logger->error("client $client_name realm id {$client->getRealmId()} doesn't match $realm_id");
            throw new InvalidInputException("invalid client for realm $realm_id");
        }
        self::validateRedirectUri($client, $redirect_uri);

        return $client;
    }

    private function checkLoginExpiration(
        Login $login,
        Realm $realm
    ) {
        $login_id = $login->getId();
        $status = $login->getStatus();
        $this->logger->info(
            "checking expiration for login $login_id in status $status"
        );

        $now = new DateTime();
        switch ($login->getStatus()) {
            case 'PENDING':
                $interval = $realm->getPendingLoginExpiresIn();
                $is_expired = $login->getCreatedAt()->add(
                    new \DateInterval("PT{$interval}S")
                ) < $now;
                break;
            case 'AUTHENTICATED':
                $interval = $realm->getAuthenticatedLoginExpiresIn();
                $is_expired = $login->getAuthenticatedAt()->add(
                    new \DateInterval("PT{$interval}S")
                ) < $now;
                break;
            case 'ACTIVE':
                $interval = $realm->getRefreshTokenExpiresIn();
                $is_expired = $login->getUpdatedAt()->add(
                    new \DateInterval("PT{$interval}S")
                ) < $now;
                break;
            default:
                $is_expired = true;
                break;
        }

        if ($is_expired) {
            $this->logger->info(
                "login $login_id in status $status expired"
            );
            $ok = $this->login_repository->setExpired($login_id);
            if (!$ok) {
                throw new StorageErrorException(
                    "unable to set login $login_id to expired"
                );
            }
            throw new InvalidInputException("$status login expired");
        }
    }

    private function checkSessionValidity(
        Session $session,
        int $exp_in_s,
        int $idle_exp_in_s
    ): bool {
        $session_id = $session->getId();
        $this->logger->info("checking expiration for session $session_id");

        $now = new DateTime('now', new \DateTimeZone('UTC'));
        $is_expired = $session->getCreatedAt()->add(
            new \DateInterval("PT{$exp_in_s}S")
        ) < $now;

        $is_idle_for_too_long = $session->getCreatedAt()->add(
            new \DateInterval("PT{$idle_exp_in_s}S")
        ) < $now;

        if (
            $is_expired || $is_idle_for_too_long
        ) {
            $this->logger->info("session $session_id expired");
            $ok = $this->session_repository->setExpired($session_id);
            if (!$ok) {
                $msg = "unable to $session_id set session to expired";
                $this->logger->error($msg);
                throw new StorageErrorException($msg);
            }
        }
        $this->logger->info("session $session_id valid");
        return true;
    }

    private static function validateScope(
        array $allowed_scope,
        string $requested_scope
    ): bool {
        $input_scope_array = explode(' ', $requested_scope);
        $valid = true;
        $required_found = false;
        foreach ($input_scope_array as $s) {
            if ($s == 'openid') {
                $required_found = true;
            }
            if (!in_array($s, $allowed_scope)) {
                $valid = false;
                break;
            }
        }
        return $valid && $required_found;
    }

    private static function validateRedirectUri(
        Client $client,
        string $redirect_uri
    ) {
        $_redirect_uri = rtrim($redirect_uri, '/');
        $_client_uri = rtrim($client->getUri(), '/');

        if (
            $_redirect_uri !== $_client_uri &&
            !self::strStartsWith($_redirect_uri, $_client_uri . '/')
        ) {
            throw new InvalidInputException('invalid redirect_uri');
        }
    }

    private static function validateQueryParams(array $query)
    {
        $required_fields = [
            'scope',
            'client_id',
            'response_type',
            'response_mode',
            'redirect_uri',
            'state',
            'nonce',
        ];

        $code_challenge_method = isset($query['code_challenge_method']) ? $query['code_challenge_method'] : null;
        if ($code_challenge_method !== null) {
            if ($code_challenge_method !== 'S256') {
                throw new InvalidInputException('unsupported code challenge method');
            }
            array_push($required_fields, 'code_challenge');
        }

        self::validateParams($query, $required_fields);

        if (!in_array($query['response_mode'], ['fragment', 'query'])) {
            throw new InvalidInputException('invalid response mode');
        }

        if (!in_array('openid', explode(' ', $query['scope']))) {
            throw new InvalidInputException('invalid scope');
        }
    }

    private static function validateTokenParams(array $query)
    {
        $required_fields = [
            'grant_type',
            'client_id',
        ];

        self::validateParams($query, $required_fields);

        if (!in_array($query['grant_type'], ['authorization_code', 'refresh_token'])) {
            throw new InvalidInputException('unsupported flow');
        }

        if ($query['grant_type'] === 'authorization_code' && !isset($query['code'])) {
            throw new InvalidInputException("missing required field 'code'");
        }
        if ($query['grant_type'] === 'refresh_token' && !isset($query['refresh_token'])) {
            throw new InvalidInputException("missing required field 'refresh_token'");
        }
    }

    private static function validateParams(
        array $params,
        array $required_fields
    ) {
        $missing = [];

        foreach ($required_fields as $f) {
            if (self::isEmpty($params[$f])) {
                array_push($missing, $f);
            }
        }
        if (count($missing) > 0) {
            $missing_str = implode(', ', $missing);
            $s = count($missing) > 1 ? 's' : '';
            throw new InvalidInputException("missing required parameter$s ($missing_str)");
        }
    }

    private function validateClientSecret(
        string $hashed_secret,
        string $client_secret
    ) {
        if (
            $client_secret == null ||
            !$this->secrets_service->validatePassword(
                $client_secret,
                $hashed_secret
            )
        ) {
            throw new InvalidInputException('invalid client secret');
        }
    }

    private static function strStartsWith(string $haystack, string $needle): bool
    {
        return substr($haystack, 0, strlen($needle)) === $needle;
    }
    private static function isEmpty(?string $param)
    {
        return !isset($param) || $param == ' ';
    }
}
