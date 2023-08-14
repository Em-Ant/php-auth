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

  public function validate_required_login_scope(
    array $realm_allowed_scope,
    string $required_scope
  ) {
    if (!self::validate_scope($realm_allowed_scope, $required_scope)) {
      $this->logger->info(
        "scope '$required_scope' not allowed for realm"
      );
      throw new InvalidInputException('scope not allowed for realm');
    }
  }

  public function initialize_login(
    array $query
  ): string {
    $client_name = $query['client_id'];
    $this->logger->info("initializing login for client $client_name");

    self::validate_query_params($query);

    $client = $this->ensure_valid_client($client_name, $query['redirect_uri']);

    $login = $this->login_repository->create_pending(
      $client->get_id(),
      $query['state'],
      $query['nonce'],
      $query['scope'],
      $query['redirect_uri'],
      $query['response_mode']
    );

    if ($login === null) {
      $msg = "unable to create pending login for $client_name";
      $this->logger->error($msg);
      throw new StorageErrorException($msg);
    }

    $login_id = $login->get_id();
    $this->logger->info("pending login $login_id created");

    return $login->get_id();
  }

  public function ensure_valid_session(
    string $session_id,
    int $session_expires_in,
    int $idle_session_expires_in
  ): ?Session {
    $session = $this->session_repository->find_by_id($session_id);
    if ($session == null || $session->get_status() != 'ACTIVE') {
      return null;
    }
    $ok = $this->check_session_validity(
      $session,
      $session_expires_in,
      $idle_session_expires_in
    );
    return $ok ? $session : null;
  }

  public function create_authorized_login(
    Session $session,
    array $query
  ): Login {
    $client_name = $query['client_id'];
    $this->logger->info("initializing login for client $client_name");

    self::validate_query_params($query);

    $client = $this->ensure_valid_client($client_name, $query['redirect_uri']);

    $user_id = $session->get_user_id();
    $user = $this->user_repository->find_by_id($user_id);

    $session_id = $session->get_id();
    if ($user == null) {
      throw new CriticalLoginErrorException(
        "invalid user $user_id for session $session_id "
      );
    }
    if (!self::validate_scope($user->get_scope(), $query['scope'])) {
      throw new CriticalLoginErrorException('invalid user scope');
    }

    $code = $this->secrets_service->generate_code();

    $login = $this->login_repository->create_authenticated(
      $client->get_id(),
      $session_id,
      $query['state'],
      $query['nonce'],
      $query['scope'],
      $query['redirect_uri'],
      $query['response_mode'],
      $code
    );

    if ($login === null) {
      throw new StorageErrorException(
        "unable to create authenticated login for session $session_id"
      );
    }

    $this->logger->info("authenticated login created");

    return $login;
  }

  public function ensure_valid_user_credentials(
    string $email,
    string $password
  ): array {
    $this->logger->info("validating user credentials for $email");

    $error = false;
    $user = $this->user_repository->find_by_email($email);
    if ($user == null) {
      $error = 'email not found';
    } else {
      $valid_pwd = $this->secrets_service->validate_password(
        $password,
        $user->get_password()
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


  public function authenticate_login(
    string $login_id,
    User $user,
    Realm $realm
  ): array {
    $this->logger->info("authenticating user for login $login_id");

    $login = $this->login_repository->find_by_id($login_id);
    if (!$login) {
      throw new StorageErrorException("unable to find login $login_id");
    }

    $this->check_login_expiration($login, $realm);

    $scope = $login->get_scope();
    if (!self::validate_scope($user->get_scope(), $scope)) {
      throw new CriticalLoginErrorException('invalid user scope');
    }

    $session = $this->session_repository->create(
      $realm->get_id(),
      $user->get_id(),
      '0'
    );
    if (!$session) {
      throw new StorageErrorException(
        "unable to create new session for login $login_id"
      );
    }

    $session_id = $session->get_id();
    $code = $this->secrets_service->generate_code();
    $ok = $this->login_repository->set_authenticated(
      $login_id,
      $session_id,
      $code
    );
    if (!$ok) {
      throw new StorageErrorException(
        "unable to authenticate login $login_id"
      );
    }

    $updated = $this->login_repository->find_by_id($login_id);

    return [
      'login' => $updated,
      'session' => $session
    ];
  }

  public function get_tokens(array $params, Realm $realm): array
  {
    $this->logger->info("generating tokens...");

    self::validate_token_params($params);
    extract($params);

    $client = $this->client_repository->find_by_name($client_id);
    if ($client === null) {
      $this->logger->info(
        "client $client_id not found while generating tokens"
      );
      throw new InvalidInputException('invalid client');
    }

    if ($client->requires_auth()) {
      $hashed_secret = $client->get_client_secret();
      $this->logger->info("$client_id requires secret validation");
      $this->validate_client_secret($hashed_secret, $client_secret ?: '');
    }

    self::validate_redirect_uri($client, $redirect_uri);

    switch ($grant_type) {
      case 'authorization_code':
        return $this->get_tokens_by_code(
          $code,
          $realm,
          $client
        );
      case 'refresh_token':
        return $this->get_tokens_by_refresh_token(
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

    $ok = $this->session_repository->set_expired($session_id);
    if (!$ok) {
      $this->logger->error("unable to transition $session_id to expired");
      throw new StorageErrorException('unable to update session');
    }
    $this->logger->info("session $session_id set to expired - logout ok");
    return $ok;
  }

  public function get_client_uri(string $client_id)
  {
    $this->logger->info("getting uri for client $client_id to enable cors on origin");
    $client = $this->client_repository->find_by_name($client_id);
    if ($client === null) {
      $this->logger->error("client $client_id not found");
      throw new InvalidInputException('invalid client_id');
    }
    return $client->get_uri();
  }

  public function parse_valid_token(string $token,  Realm $realm): array
  {
    $is_valid = $this->token_service->validateToken($token, $realm);
    $is_expired = $this->token_service->tokenIsExpired($token);
    if(!$is_valid) {
      $this->logger->error("invalid token");
      throw new InvalidInputException('Token verification failed');
    }
    if($is_expired) {
      $this->logger->error("token expired");
      throw new InvalidInputException('Token is expired');
    }

    return $this->token_service->decodeTokenPayload($token);
  }

  private function get_tokens_by_code(
    string $code,
    Realm $realm,
    Client $client
  ): array {
    $this->logger->info("generating tokens from authorization code $code");
    $login = $this->login_repository->find_by_code($code);
    if ($login === null) {
      $this->logger->error("invalid authorization code");
      throw new InvalidInputException('invalid code');
    }
    if ($login->get_status() != 'AUTHENTICATED') {
      $this->logger->error("code $code is expired");
      throw new InvalidInputException('code is expired');
    }

    $this->check_login_expiration($login, $realm);

    $session_id = $login->get_session_id();
    $session = $this->session_repository->find_by_id($session_id);
    if ($session == null) {
      throw new StorageErrorException("invalid session $session_id");
    }

    $ok = $this->check_session_validity(
      $session,
      $realm->get_session_expires_in(),
      $realm->get_idle_session_expires_in()
    );
    if (!$ok) {
      $this->logger->error("session $session_id expired");
      throw new InvalidInputException('session expired');
    }

    $user = $this->user_repository->find_by_id($session->get_user_id());
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

    $login_id = $login->get_id();
    $ok = $this->login_repository->set_active(
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

  private function get_tokens_by_refresh_token(
    string $refresh_token,
    Realm $realm,
    Client $client
  ): array {
    $this->logger->info("generating tokens from refresh token");

    $login = $this->login_repository->find_by_refresh_token($refresh_token);
    if ($login === null) {
      $this->logger->error("invalid refresh token");
      throw new InvalidInputException('invalid refresh token');
    }
    if ($login->get_status() != 'ACTIVE') {
      $this->logger->error("login is in invalid status");
      throw new InvalidInputException('login is expired');
    }
    $login_id = $login->get_id();

    $this->check_login_expiration($login, $realm);

    $expired = $this->token_service->tokenIsExpired($refresh_token);
    if ($expired) {
      $ok = $this->login_repository->set_expired($login_id);
      if (!$ok) {
        $this->logger->error("unable to set session $login_id to expired");
        throw new StorageErrorException('unable to set session to expired');
      }
      throw new InvalidInputException('refresh_token is expired');
    }

    $session_id = $login->get_session_id();
    $session = $this->session_repository->find_by_id($session_id);
    if ($session == null) {
      throw new StorageErrorException("invalid session $session_id");
    }
    if ($session->get_status() != 'ACTIVE') {
      $this->logger->error("invalid status for session $session_id - not active");
      throw new InvalidInputException('invalid session status');
    }


    $ok = $this->check_session_validity(
      $session,
      $realm->get_session_expires_in(),
      $realm->get_idle_session_expires_in()
    );
    if (!$ok) {
      $this->logger->error("session $session_id expired");
      throw new InvalidInputException('session expired');
    }

    $user = $this->user_repository->find_by_id($session->get_user_id());
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

  private function ensure_valid_client(
    string $client_name,
    string $redirect_uri
  ) {
    $client = $this->client_repository->find_by_name($client_name);
    if ($client === null) {
      $this->logger->error("client matching $client_name not found for realm");
      throw new InvalidInputException('invalid client id');
    }
    self::validate_redirect_uri($client, $redirect_uri);

    return $client;
  }

  private function check_login_expiration(
    Login $login,
    Realm $realm
  ) {
    $login_id = $login->get_id();
    $status = $login->get_status();
    $this->logger->info(
      "checking expiration for login $login_id in status $status"
    );

    $now = new DateTime();
    switch ($login->get_status()) {
      case 'PENDING':
        $interval = $realm->get_pending_login_expires_in();
        $is_expired = $login->get_created_at()->add(
          new \DateInterval("PT{$interval}S")
        ) < $now;
        break;
      case 'AUTHENTICATED':
        $interval = $realm->get_authenticated_login_expires_in();
        $is_expired = $login->get_authenticated_at()->add(
          new \DateInterval("PT{$interval}S")
        ) < $now;
        break;
      case 'ACTIVE':
        $interval = $realm->get_refresh_token_expires_in();
        $is_expired = $login->get_updated_at()->add(
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
      $ok = $this->login_repository->set_expired($login_id);
      if (!$ok) {
        throw new StorageErrorException(
          "unable to set login $login_id to expired"
        );
      }
      throw new InvalidInputException("$status login expired");
    }
  }

  private function check_session_validity(
    Session $session,
    int $exp_in_s,
    int $idle_exp_in_s
  ): bool {
    $session_id = $session->get_id();
    $this->logger->info("checking expiration for session $session_id");

    $now = new DateTime('now', new \DateTimeZone('UTC'));
    $is_expired = $session->get_created_at()->add(
      new \DateInterval("PT{$exp_in_s}S")
    ) < $now;

    $is_idle_for_too_long = $session->get_created_at()->add(
      new \DateInterval("PT{$idle_exp_in_s}S")
    ) < $now;

    if (
      $is_expired || $is_idle_for_too_long
    ) {
      $this->logger->info("session $session_id expired");
      $ok = $this->session_repository->set_expired($session_id);
      if (!$ok) {
        $msg = "unable to $session_id set session to expired";
        $this->logger->error($msg);
        throw new StorageErrorException($msg);
        return false;
      }
    }
    $this->logger->info("session $session_id valid");
    return true;
  }

  private static function validate_scope(
    array $allowed_scope,
    string $requested_scope
  ): bool {
    $input_scope_array = explode(' ', $requested_scope);
    $valid = TRUE;
    foreach ($input_scope_array as $s) {
      if ($s == 'openid') {
        continue;
      }
      if (!in_array($s, $allowed_scope)) {
        $valid = FALSE;
        break;
      }
    }
    return $valid;
  }

  private static function validate_redirect_uri(
    Client $client,
    string $redirect_uri
  ) {
    $_redirect_uri = rtrim($redirect_uri, '/');
    $_client_uri = rtrim($client->get_uri(), '/');

    if (
      $_redirect_uri !== $_client_uri &&
      !self::str_starts_with($_redirect_uri, $_client_uri . '/')
    ) {
      throw new InvalidInputException('invalid redirect_uri');
    }
  }

  private static function validate_query_params(array $query)
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

    self::validate_params($query, $required_fields);

    if (!in_array($query['response_mode'], ['fragment', 'query'])) {
      throw new InvalidInputException('invalid response mode');
    }

    if (!in_array('openid', explode(' ', $query['scope']))) {
      throw new InvalidInputException('invalid scope');
    }
  }

  private static function validate_token_params(array $query)
  {
    $required_fields = [
      'grant_type',
      'client_id',
      'redirect_uri'
    ];

    self::validate_params($query, $required_fields);

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

  private static function validate_params(
    array $params,
    array $required_fields
  ) {
    $missing = [];

    foreach ($required_fields as $f) {
      if (self::is_empty($params[$f])) {
        array_push($missing, $f);
      }
    }
    if (count($missing) > 0) {
      $missing_str = implode(', ', $missing);
      $s = count($missing) > 1 ? 's' : '';
      throw new InvalidInputException("missing required parameter$s ($missing_str)");
    }
  }

  private function validate_client_secret(
    string $hashed_secret,
    string $client_secret
  ) {
    if (
      $client_secret == null ||
      !$this->secrets_service->validate_password(
        $client_secret,
        $hashed_secret
      )
    ) {
      throw new InvalidInputException('invalid client secret');
    }
  }

  private static function str_starts_with(string $haystack, string $needle): bool
  {
    return substr($haystack, 0, strlen($needle)) === $needle;
  }
  private static function is_empty(?string $param)
  {
    return !isset($param) || $param == ' ';
  }
}
