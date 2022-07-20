<?php

namespace AuthServer\Interfaces;

use AuthServer\Models\Login;

require_once 'src/models/session.php';

interface LoginRepository
{
  public function find_by_id(string $id): ?Login;
  public function find_by_code(string $code): ?Login;
  public function find_by_refresh_token(string $token): ?Login;

  public function create_pending(
    string $client_id,
    string $state,
    string $nonce,
    string $scope,
    string $redirect_uri,
    string $response_mode
  ): ?Login;

  public function create_authenticated(
    string $client_id,
    string $session_id,
    string $state,
    string $nonce,
    string $scope,
    string $redirect_uri,
    string $response_mode,
    string $code
  ): ?Login;

  public function set_authenticated(
    string $id,
    string $code
  ): bool;

  public function set_active(
    string $id,
    string $token
  ): bool;

  public function refresh(
    string $id,
    string $token
  ): bool;
}
