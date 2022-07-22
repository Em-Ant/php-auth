<?php

declare(strict_types=1);

namespace AuthServer\Controllers;

use AuthServer\Exceptions\CriticalLoginErrorException;
use AuthServer\Lib\Utils;
use AuthServer\Exceptions\InvalidInputException;
use AuthServer\Models\Login;
use AuthServer\Models\Realm;
use AuthServer\Services\AuthorizeService;

require_once 'src/lib/utils.php';
require_once 'src/exceptions/invalid_input_exception.php';
require_once 'src/exceptions/critical_login_error_exception.php';

class Authorize
{
  private AuthorizeService $auth_service;
  private string $issuer;
  private string $mount_path;

  const INVALID_REQUEST = 'Invalid request';

  public function __construct(
    AuthorizeService $service,
    string $issuer,
    string $mount_path
  ) {
    $this->auth_service = $service;
    $this->issuer = $issuer;
    $this->mount_path = $mount_path;
  }

  public function authorize(array $ctx)
  {
    /** @var Realm */
    $realm = $ctx['realm'];

    $realm_name = $realm->get_name();
    $current_session_id =
      self::get_session_id_from_cookie($realm_name);

    try {
      $query = $ctx['query'];
      $scope = $query['scope'];

      $this->auth_service->validate_required_login_scope(
        $realm->get_scope(),
        $scope
      );

      if ($current_session_id) {

        // self::set_session_cookie($realm, $current_session_id, 'localhost');

        $result = $this->auth_service->create_authorized_login(
          $current_session_id,
          $query,
          $realm->get_session_expires_in(),
          $realm->get_idle_session_expires_in()
        );

        /** @var Login */
        $login = $result['login'];
        /** @var Session */
        $session = $result['session'];

        $redirect_uri = self::get_redirect_uri($login, $session->get_id());

        header("location: $redirect_uri", true, 302);
        die();
      } else {
        $pending_login_id = $this->auth_service->initialize_login(
          $query
        );
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
      $sub = $this->mount_path ?: '';
      $realm_name = $realm->get_name();
      header(
        "location: $sub/realms/$realm_name/protocol/openid-connect/error?e=$message",
        true,
        302
      );
      die();
    }
  }

  public function login(array $ctx)
  {
    $query = $ctx['query'];
    $body = $ctx['body'];

    /** @var Realm */
    $realm = $ctx['realm'];

    $email = $body['email'];
    $password = $body['password'];

    $login_id = $query['q'];

    $result = $this->auth_service->ensure_valid_user_credentials(
      $email,
      $password,
    );
    if ($result['error']) {
      Utils::show_view(
        'login_form',
        [
          'title' => 'Login',
          'login_id' => $login_id,
          'realm' => $realm->get_name(),
          'email' => $email,
          'password' => $password,
          'error' => $result['error']
        ]
      );
      die();
    }

    try {
      $data = $this->auth_service->authenticate_login(
        $login_id,
        $result['user'],
        $realm
      );

      $session_id = (string) $data['session']->get_id();
      /** @var Login */
      $login = $data['login'];
      $redirect_uri = self::get_redirect_uri($login, $session_id);

      // self::set_session_cookie($realm, $session_id, 'localhost');

      header("location: $redirect_uri", true, 302);
      die();
    } catch (CriticalLoginErrorException $e) {
      $message = $e->getMessage();
      $sub = $GLOBALS['sub_path'] ?: '';
      header("location: $sub/realms//error?e=$message", true, 302);
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
      $realm = $ctx['realm'];
      $origin = $this->auth_service->get_client_uri($body['client_id']);
      Utils::enable_cors($origin);
      Utils::send_json($this->auth_service->get_tokens($body, $realm));
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
    /** @var Realm */
    $realm = $ctx['realm'];
    $query = $ctx['query'];
    $redirect = $query['post_logout_redirect_uri'];
    $id_token = $query['id_token_hint'];
    try {
      $this->auth_service->logout($id_token, $realm);
      header("location: $redirect", true, 302);
      die();
    } catch (InvalidInputException $e) {
      Utils::server_error(self::INVALID_REQUEST, $e->getMessage(), 400);
    }
  }

  public function send_keys(array $ctx)
  {
    /** @var Realm */
    $realm = $ctx['realm'];
    $kid = $realm->get_keys_id();
    $keys = file_get_contents("keys/$kid/keys.json", true);
    header('Content-Type: application/json; charset=utf-8');
    Utils::enable_cors();
    echo $keys;
    die();
  }

  public function send_config()
  {
    $data = file_get_contents('./static/well-known.json', true);
    header('Content-Type: application/json; charset=utf-8');
    Utils::enable_cors();
    echo str_replace('<<ISSUER>>', $this->issuer, $data);
    die();
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

  private static function get_redirect_uri(
    Login $login,
    string $session_id
  ): string {
    $redirect_uri = $login->get_redirect_uri();
    $response_mode = $login->get_response_mode();
    $append = '';
    $char = '';
    $hash_pos = strpos($redirect_uri, '#');

    if ($response_mode == 'query') {
      $char = strpos($redirect_uri, '?') ? '&' : '?';
      if ($hash_pos) {
        $append = substr($redirect_uri, $hash_pos);
        $redirect_uri = substr($redirect_uri, 0, $hash_pos);
      }
    } else {
      $char = $hash_pos ? '&' : '#';
    }

    return $redirect_uri . $char .
      'code=' . $login->get_code() .
      '&state=' . $login->get_state() .
      '&session_state=' . $session_id .
      $append;
  }
}
