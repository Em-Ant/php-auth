<?php

declare(strict_types=1);

namespace AuthServer\Controllers;

use AuthServer\Exceptions\CriticalLoginErrorException;
use AuthServer\Lib\Utils;
use AuthServer\Exceptions\InvalidInputException;
use AuthServer\Models\Realm;
use AuthServer\Services\AuthorizeService;

require_once 'src/lib/utils.php';
require_once 'src/exceptions/invalid_input_exception.php';
require_once 'src/exceptions/critical_login_error_exception.php';

class Authorize
{
  private AuthorizeService $auth_service;

  const INVALID_REQUEST = 'Invalid request';

  public function __construct(
    // AuthorizeService $service
  )
  {
    //$this->auth_service = $service;
  }

  public function authorize(array $ctx)
  {
    $realm = $ctx['realm'];
    $realm_name = $realm->get_name();
    $current_session_id =
      self::get_session_id_from_cookie($realm_name);

    // login
    try {
      $query = $ctx['query'];
      if ($current_session_id) {
        self::set_session_cookie($realm, $current_session_id, 'localhost');

        $redirect_uri = /* authorize_login($realm, $current_session_id, $query); */ '';
        header("location: $redirect_uri", true, 302);
        die();
      } else {
        $pending_login_id = /* init_login($query); */ '';
        Utils::show_view(
          'login_form',
          [
            'title' => 'Login',
            'login_id' => $pending_login_id,
            'realm' => $realm_name,
            'email' => '',
            'password' => '',
            'error' => false
          ]
        );
        die();
      }
    } catch (InvalidInputException $e) {
      Utils::server_error(self::INVALID_REQUEST, $e->getMessage(), 400);
    } catch (CriticalLoginErrorException $e) {
      $message = $e->getMessage();
      $sub = $GLOBALS['sub_path'] ?: '';
      header("location: $sub/error?e=$message", true, 302);
    }
  }

  /*
  public function authorize(array $ctx)
  {
    try {
      $query = $ctx['query'];
      $session_id = $this->auth_service->create_session($query);
      Utils::show_view(
        'login_form',
        [
          'title' => 'Login',
          'session_id' => $session_id,
          'realm' => 'web',
          'response_mode' => $query['response_mode'],
          'scopes' => $query['scope'],
          'email' => '',
          'password' => '',
          'error' => false
        ]
      );
      die();
    } catch (InvalidInputException $e) {
      Utils::server_error(self::INVALID_REQUEST, $e->getMessage(), 400);
    }
  }

  public function login(array $ctx)
  {
    $query = $ctx['query'];
    $body = $ctx['body'];

    $sessionId = $query['q'];
    $scopes = $query['s'];
    $response_mode = $query['m'];
    $email = $body['email'];
    $password = $body['password'];

    $result = $this->auth_service->ensure_valid_user_credentials(
      $email,
      $password,
    );
    if ($result['error']) {
      Utils::show_view(
        'login_form',
        [
          'title' => 'Login',
          'session_id' => $sessionId,
          'realm' => 'web',
          'scopes' => $scopes,
          'email' => $email,
          'password' => $password,
          'error' => $result['error']
        ]
      );
      die();
    }

    try {
      $redirect_uri = $this->auth_service->authenticate(
        $result['user'],
        $sessionId,
        $scopes,
        $response_mode
      );
      setcookie('AUTH_SESSION', $sessionId, [
        'expires' => time() + 86400,
        'path' => '/realms/web',
        'domain' => 'localhost',
        'httponly' => true,
        'secure' => true,
        'samesite' => 'None',
      ]);
      header("location: $redirect_uri", true, 302);
      die();
    } catch (CriticalLoginErrorException $e) {
      $message = $e->getMessage();
      $sub = $GLOBALS['sub_path'] ?: '';
      header("location: $sub/error?e=$message", true, 302);
    }
  }

  public function token(array $ctx)
  {
    $body = $ctx['body'];
    if (!isset($body['client_id'])) {
      $body['client_id'] = isset($ctx['basic_auth_user'])
        ? $ctx['basic_auth_user']
        : null;
    }

    if (!isset($body['client_secret'])) {
      $body['client_secret'] = isset($ctx['basic_auth_pwd'])
        ? $ctx['basic_auth_pwd']
        : null;
    }

    try {
      $origin = $this->auth_service->get_client_uri($body['client_id']);
      Utils::enable_cors($origin);
      Utils::send_json($this->auth_service->get_tokens($body));
    } catch (InvalidInputException $e) {
      Utils::server_error(self::INVALID_REQUEST, $e->getMessage(), 400);
    }
  }

  public function error(array $ctx)
  {
    $message = $ctx['query']['e'];
    Utils::show_view('error', [
      'title' => 'Error',
      'error' => $message
    ]);
  }

  public function logout(array $ctx)
  {
    $query = $ctx['query'];
    $redirect = $query['post_logout_redirect_uri'];
    $id_token = $query['id_token_hint'];
    try {
      $this->auth_service->logout($id_token);
      header("location: $redirect", true, 302);
      die();
    } catch (InvalidInputException $e) {
      Utils::server_error(self::INVALID_REQUEST, $e->getMessage(), 400);
    }
  }

  */
  public static function send_keys(array $ctx)
  {
    $kid = $ctx['realm']->get_keys_id();
    $keys = file_get_contents("keys/$kid/keys.json", true);
    header('Content-Type: application/json; charset=utf-8');
    Utils::enable_cors();
    echo $keys;
    die();
  }

  public static function send_config(string $issuer)
  {
    return function () use ($issuer) {
      $data = file_get_contents('./static/well-known.json', true);
      header('Content-Type: application/json; charset=utf-8');
      Utils::enable_cors();
      echo str_replace('<<ISSUER>>', $issuer, $data);
      die();
    };
  }

  private static function get_session_id_from_cookie(
    string $realm_name
  ): ?string {
    $session_cookie = $_COOKIE['AUTH_SESSION'];

    if (!$session_cookie) {
      return null;
    }

    $parts = explode('\\', $session_cookie);
    $cookie_realm_name = $parts[0];
    $session_id = $parts[1];

    if ($realm_name != $cookie_realm_name) {
      return null;
    }

    return $session_id;
  }

  private static function set_session_cookie(
    Realm $realm,
    string $session_id,
    $domain
  ) {
    $realm_name = $realm->get_name();
    setcookie('AUTH_SESSION', "$realm_name\\$session_id", [
      'expires' => time() + $realm->get_session_expires_in(),
      'path' => "/realms/$realm_name",
      'domain' => $domain,
      'httponly' => true,
      'secure' => true,
      'samesite' => 'None',
    ]);
  }
}
