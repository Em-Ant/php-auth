<?php

namespace AuthServer\Services;

use AuthServer\Exceptions\InvalidInputException;
use AuthServer\Exceptions\StorageErrorException;
use AuthServer\Exceptions\CriticalLoginErrorException;
use AuthServer\Interfaces\ClientRepository as IClientRepo;
use AuthServer\Interfaces\SessionRepository as ISessionRepo;
use AuthServer\Interfaces\UserRepository as IUserRepo;

use AuthServer\Lib\Utils;
use AuthServer\Models\Client;
use AuthServer\Models\Session;
use AuthServer\Models\User;
use Error;

use function PHPSTORM_META\map;

require_once 'src/interfaces/client_repository.php';
require_once 'src/interfaces/session_repository.php';
require_once 'src/interfaces/user_repository.php';

require_once 'src/services/secrets_service.php';

require_once 'src/exceptions/invalid_input_exception.php';
require_once 'src/exceptions/storage_error_exception.php';
require_once 'src/exceptions/critical_login_error_exception.php';

class AuthorizeService
{
  private IClientRepo $client_repository;
  private ISessionRepo $session_repository;
  private IUserRepo $user_repository;
  private SecretsService $secrets_service;

  public function __construct(
    IClientRepo $client_repo,
    ISessionRepo $session_repo,
    IUserRepo $user_repo,
    SecretsService $secrets_service
  ) {
    $this->client_repository = $client_repo;
    $this->session_repository = $session_repo;
    $this->user_repository = $user_repo;
    $this->secrets_service = $secrets_service;
  }

  public function show_login_form(array $query)
  {
    self::validate_query_params($query);
    $client = $this->get_client($query['client_id']);
    self::validate_redirect_uri($client, $query['redirect_uri']);
    self::validate_client_scopes($client, $query['scope']);
    $session = $this->create_pending_session(
      $client->get_id(),
      $query['state'],
      $query['nonce'],
      $query['redirect_uri']
    );
    Utils::show_view(
      'login_form',
      [
        'title' => 'Login',
        'session_id' => $session->get_id(),
        'scopes' => $query['scope']
      ]
    );
  }

  public function authenticate(
    string $email,
    string $password,
    string $sessionId,
    string $scopes
  ): ?Session {
    $user = $this->user_repository->findByEmail($email);
    $error = null;
    if ($user == null) {
      $error = 'email not found';
    } else {
      $valid_pwd = $this->secrets_service->validate_password(
        $password,
        $user->get_password()
      );
      if (!$valid_pwd) $error = 'invalid password';
    }

    if ($error) {
      Utils::show_view(
        'login_form',
        [
          'title' => 'Login',
          'session_id' => $sessionId,
          'scopes' => $scopes,
          'password' => $password,
          'email' => $email,
          'error' => $error
        ]
      );
      die();
    }

    $valid_user_scopes = self::validate_user_scopes($user, $scopes);
    if (!$valid_user_scopes)
      throw new CriticalLoginErrorException('invalid user scopes');

    $session = $this->session_repository->findById($sessionId);
    if ($session == null || $session->get_status() != 'PENDING') {
      throw new CriticalLoginErrorException('invalid session');
    }

    $session = $this->session_repository->updateWithUserIdAndCode(
      $sessionId,
      $user->get_id(),
      $this->secrets_service->generate_code()
    );

    return $session;
  }

  private function create_pending_session(
    string $client_id,
    string $state,
    string $nonce,
    string $redirect_uri
  ): Session {
    $session = $this->session_repository->createPending(
      $client_id,
      $state,
      $nonce,
      $redirect_uri
    );
    if ($session === null) {
      throw new StorageErrorException('unable to create session');
    }
    return $session;
  }

  private function get_client(string $client_id): Client
  {
    $client = $this->client_repository->findByClientId($client_id);
    if ($client === null) {
      throw new InvalidInputException('invalid client id');
    }
    return $client;
  }

  private static function validate_scopes(
    array $allowed_scopes,
    string $requested_scopes
  ): bool {
    $input_scopes_array = explode(' ', $requested_scopes);
    $valid = TRUE;
    foreach ($input_scopes_array as $s) {
      if ($s == 'openid') continue;
      if (!in_array($s, $allowed_scopes)) {
        $valid = FALSE;
        break;
      }
    }
    return $valid;
  }
  private static function validate_client_scopes(Client $client, string $scopes)
  {
    if (!self::validate_scopes($client->get_scopes(), $scopes)) {
      throw new InvalidInputException('scopes not allowed for client');
    }
  }
  private static function validate_user_scopes(User $user, string $scopes): bool
  {
    return self::validate_scopes($user->get_scopes(), $scopes);
  }

  private static function validate_redirect_uri(Client $client, string $redirect_uri)
  {
    $_redirect_uri = rtrim($redirect_uri, '/');
    $_client_uri = rtrim($client->get_uri(), '/');

    if (
      $_redirect_uri !== $_client_uri &&
      !self::str_starts_with($_redirect_uri, $_client_uri . '/')
    ) {
      throw new InvalidInputException('invalid redirect_uri');
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

  private static function validate_query_params(array $query)
  {
    $missing = [];
    $required_fields = [
      'scope',
      'client_id',
      'response_type',
      'response_mode',
      'redirect_uri',
      'state',
      'nonce'
    ];

    foreach ($required_fields as $f) {
      if (self::is_empty($query[$f])) {
        array_push($missing, $f);
      }
    }
    if (count($missing) > 0) {
      $missing_str = implode(', ', $missing);
      $s = count($missing) > 1 ? 's' : '';
      throw new InvalidInputException("missing required parameter$s ($missing_str)");
    }

    if ($query['response_type'] !== 'code') {
      throw new InvalidInputException('unsupported flow');
    }

    if (!in_array($query['response_mode'], ['fragment', 'query'])) {
      throw new InvalidInputException('invalid response mode');
    }

    if (!in_array('openid', explode(' ', $query['scope']))) {
      throw new InvalidInputException('invalid scope');
    }
  }
}
