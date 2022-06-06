<?php

declare(strict_types=1);

namespace AuthServer\Controllers;

use AuthServer\Lib\Utils;
use AuthServer\Exceptions\InvalidInputException;
use AuthServer\Interfaces\SessionRepository;
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
    header('location: http://localhost:3000', true, 302);
    die();
  }
}
