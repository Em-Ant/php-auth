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

  public function authorize()
  {
    try {
      $this->auth_service->show_login($_GET);
    } catch (InvalidInputException $e) {
      Utils::server_error('invalid request', $e->getMessage(), 400);
    }
  }

  public function login()
  {
    $sessionId = $_GET['q'];
    $scopes = $_GET['s'];
    $response_mode = $_GET['m'];
    $email = $_POST['email'];
    $password = $_POST['password'];

    try {
      $location = $this->auth_service->authenticate(
        $email,
        $password,
        $sessionId,
        $scopes,
        $response_mode
      );
      header("location: $location", true, 302);
      die();
    } catch (CriticalLoginErrorException $e) {
      $message = $e->getMessage();
      $sub = $GLOBALS['sub_path'] ?: '';
      header("location: $sub/error?e=$message", true, 302);
    }
  }

  public function token()
  {
    try {
      $origin = $this->auth_service->get_client_uri($_POST['client_id']);
      header("Access-Control-Allow-Origin: $origin");
      header('Access-Control-Allow-Credentials: true');
      header('Access-Control-Allow-Headers:content-type,accept,origin');
      header('Access-Control-Allow-Methods:GET,POST,OPTIONS');

      Utils::send_json($this->auth_service->get_tokens($_POST));
    } catch (InvalidInputException $e) {
      Utils::server_error('invalid request', $e->getMessage(), 400);
    }
  }

  public function error(array $params)
  {
    $message = $_GET['e'];
    Utils::show_view('error', [
      'title' => 'Error',
      'error' => $message
    ]);
  }

  public function logout()
  {
    $redirect = $_GET['post_logout_redirect_uri'];
    $id_token = $_GET['id_token_hint'];
    $this->auth_service->logout($id_token);
    header("location: $redirect", true, 302);
    die();
  }
}
