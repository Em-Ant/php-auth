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

require_once 'src/exceptions/invalid_input_exception.php';
require_once 'src/exceptions/storage_error_exception.php';
require_once 'src/exceptions/critical_login_error_exception.php';

require_once 'src/interfaces/client_repository.php';
require_once 'src/interfaces/session_repository.php';
require_once 'src/interfaces/user_repository.php';
require_once 'src/interfaces/login_repository.php';

require_once 'src/interfaces/logger.php';

require_once 'src/services/secrets_service.php';
require_once 'src/services/secrets_service.php';

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

  public static function validate_required_login_scopes(
    array $realm_allowed_scopes,
    string $required_scopes
  ) {
    if (!self::validate_scopes($realm_allowed_scopes, $required_scopes)) {
      throw new InvalidInputException('scopes not allowed for realm');
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
      throw new StorageErrorException(
        "unable to create pending login for $client_name"
      );
    }

    $this->logger->info("pending login created");

    return $login->get_id();
  }

  public function create_authorized_login(
    string $session_id,
    array $query,
    int $session_expires_in,
    int $idle_session_expires_in
  ): array {
    $client_name = $query['client_id'];
    $this->logger->info("initializing login for client $client_name");

    self::validate_query_params($query);

    $client = $this->ensure_valid_client($client_name, $query['redirect_uri']);

    $session = $this->session_repository->find_by_id($session_id);
    if ($session == null || $session->get_status() != 'ACTIVE') {
      throw new CriticalLoginErrorException(
        "invalid session $session_id - not in ACTIVE status"
      );
    }
    $this->check_session_expiration(
      $session,
      $session_expires_in,
      $idle_session_expires_in
    );

    $user_id = $session->get_user_id();
    $user = $this->user_repository->find_by_id($user_id);
    if ($user == null) {
      throw new CriticalLoginErrorException(
        "invalid user $user_id for session $session_id "
      );
    }
    if (!self::validate_scopes($user->get_scopes(), $query['scope'])) {
      throw new CriticalLoginErrorException('invalid user scopes');
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

    return [
      'login' => $login,
      'session' => $session
    ];
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
    User $user,
    string $login_id,
    string $realm_id
  ): array {
    $this->logger->info("authenticating user for login $login_id");

    $login = $this->login_repository->find_by_id($login_id);
    if (!$login) {
      throw new StorageErrorException("unable to find login $login_id");
    }

    $scopes = $login->get_scopes();
    if (!self::validate_scopes($user->get_scopes(), $scopes)) {
      throw new CriticalLoginErrorException('invalid user scopes');
    }

    $session = $this->session_repository->create(
      $realm_id,
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

    return [
      'login' => $login,
      'session' => $session
    ];
  }

  public function get_tokens(array $params): array
  {
    $this->logger->info("generating tokens...");

    self::validate_token_params($params);
    extract($params);

    $client = $this->client_repository->find_by_name($client_id);
    if ($client === null) {
      throw new InvalidInputException("client $client_id not found while generating tokens");
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
          $client
        );
      case 'refresh_token':
        $this->logger->info("generating tokens from refresh token");
        return $this->get_tokens_by_refresh_token(
          $refresh_token,
          $client
        );
      default:
        $this->logger->error("unsupported token flow $grant_type");
        throw new InvalidInputException('unsupported flow');
    }
  }

  public function logout(
    string $id_token
  ): bool {
    $this->logger->info("logging out for id token");
    $token_valid = $this->token_service->validateToken($id_token);
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

  private function get_tokens_by_code(
    string $code,
    Client $client
  ): array {
    /*
    $this->logger->info("generating tokens from authorization code $code");
    $session = $this->session_repository->find_by_code($code);
    if ($session === null) {
      $this->logger->error("invalid authorization code");
      throw new InvalidInputException('invalid code');
    }
    if ($session->get_status() != 'AUTHENTICATED') {
      $this->logger->error("code $code is expired");
      throw new InvalidInputException('code is expired');
    }

    $this->check_session_expiration(
      $session,
      $this->authenticated_session_expires_in_seconds
    );

    $user = $this->user_repository->find_by_id($session->get_user_id());
    if ($user == null) {
      throw new StorageErrorException('invalid session');
    }

    $token_bundle = $this->token_service->createTokenBundle(
      $session,
      $client,
      $user,
      $this->access_token_expires_in_seconds,
      $this->refresh_token_expires_in_seconds,
      '1'
    );

    $updated_session = $this->session_repository->setActive(
      $session->get_id(),
      $token_bundle['refresh_token']
    );
    if (!$updated_session) {
      throw new StorageErrorException('error updating session');
    }

    return $token_bundle;
    */
    return [];
  }

  private function get_tokens_by_refresh_token(
    string $refresh_token,
    Client $client
  ): array {
    /*
    $this->logger->info("generating tokens from refresh token");

    $session = $this->session_repository->find_by_refresh_token($refresh_token);

    if ($session === null) {
      throw new InvalidInputException('invalid refresh_token');
    }
    $session_id = $session->get_id();
    $this->logger->info("session $session_id found for refresh token");

    $expired = $this->token_service->tokenIsExpired($refresh_token);
    if ($expired) {
      $ok = $this->session_repository->set_expired($session_id);
      if (!$ok) {
        $this->logger->error("unable to set session $session_id to expired");
        throw new StorageErrorException('unable to set session to expired');
      }
      throw new InvalidInputException('refresh_token is expired');
    }
    if ($session->get_status() != 'ACTIVE') {
      $this->logger->error("invalid status for session $session_id - not active");
      throw new InvalidInputException('invalid session status');
    }
    $user = $this->user_repository->find_by_id($session->get_user_id());
    if ($user == null) {
      $this->logger->error("active $session_id not found");
      throw new StorageErrorException('invalid session');
    }
    $token_bundle = $this->token_service->createTokenBundle(
      $session,
      $client,
      $user,
      $this->access_token_expires_in_seconds,
      $this->refresh_token_expires_in_seconds,
      '1'
    );
    $updated_session = $this->session_repository->updateRefreshToken(
      $session_id,
      $token_bundle['refresh_token']
    );
    if (!$updated_session) {
      $this->logger->error("could not update session $session_id with refresh token");
      throw new StorageErrorException('error updating session');
    }
    return $token_bundle;
    */
    return [];
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

  private function check_session_expiration(
    Session $session,
    int $exp_in_s,
    int $idle_exp_in_s,
    ?string $msg = 'session expired'
  ): void {
    $session_id = $session->get_id();
    $this->logger->info("checking expiration fpr $session_id (valid: $exp_in_s s)");

    $is_expired = $session->get_created_at()->add(
      new \DateInterval("PT{$exp_in_s}S")
    ) > new DateTime();

    $is_idle_for_too_long = $session->get_created_at()->add(
      new \DateInterval("PT{$idle_exp_in_s}S")
    ) > new DateTime();

    if (
      $is_expired || $is_idle_for_too_long
    ) {
      $this->logger->info("session $session_id expired");
      $ok = $this->session_repository->set_expired($session_id);
      if (!$ok) {
        throw new StorageErrorException(
          "unable to $session_id set session to expired"
        );
      }
      throw new InvalidInputException($msg);
    }
    $this->logger->info("session $session_id not expired");
  }

  private static function validate_scopes(
    array $allowed_scopes,
    string $requested_scopes
  ): bool {
    $input_scopes_array = explode(' ', $requested_scopes);
    $valid = TRUE;
    foreach ($input_scopes_array as $s) {
      if ($s == 'openid') {
        continue;
      }
      if (!in_array($s, $allowed_scopes)) {
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
