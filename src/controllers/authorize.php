<?php

declare(strict_types=1);

namespace AuthServer\Controllers;

use AuthServer\Exceptions\CriticalLoginErrorException;
use AuthServer\Lib\Utils;
use AuthServer\Exceptions\InvalidInputException;
use AuthServer\Services\AuthorizeService;

require_once 'src/lib/utils.php';
require_once 'src/exceptions/invalid_input_exception.php';
require_once 'src/exceptions/critical_login_error_exception.php';

class Authorize
{
  private AuthorizeService $auth_service;

  public function __construct(
    AuthorizeService $service
  ) {
    $this->auth_service = $service;
  }

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
      Utils::server_error('invalid request', $e->getMessage(), 400);
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
      Utils::server_error('invalid request', $e->getMessage(), 400);
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
    $this->auth_service->logout($id_token);
    header("location: $redirect", true, 302);
    die();
  }

  public static function send_keys(string $kid)
  {
    return function () use ($kid) {
      $keys = file_get_contents("keys/$kid/keys.json", true);
      header('Content-Type: application/json; charset=utf-8');
      echo $keys;
      die();
    };
  }
}
