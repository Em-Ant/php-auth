<?php

declare(strict_types=1);

namespace AuthServer\Controllers;

use AuthServer\Lib\Utils;
use AuthServer\Exceptions\InvalidInputException;
use AuthServer\Services\AuthorizeService;

require_once 'src/lib/utils.php';
require_once 'src/exceptions/invalid_input_exception.php';

class Authorize
{
  private AuthorizeService $auth_service;

  public function __construct(
    AuthorizeService $service
  ) {
    $this->auth_service = $service;
  }
  public function authorize(array $params)
  {
    try {
      $this->auth_service->show_login_form($_GET);
    } catch (InvalidInputException $e) {
      Utils::server_error('invalid request', $e->getMessage(), 400);
    }
  }
  public function login(array $params)
  {
    $sessionId = $_GET['q'];
    $scopes = $_GET['s'];
    $email = $_POST['email'];
    $password = $_POST['password'];

    $session = $this->auth_service->authenticate(
      $email,
      $password,
      $sessionId,
      $scopes
    );
    $location = $session->get_redirect_uri() .
      '?code=' . $session->get_code() .
      '&state=' . $session->get_state();

    header("location: $location", true, 302);
    die();
  }
}
