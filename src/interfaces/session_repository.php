<?php

namespace AuthServer\Interfaces;

use AuthServer\Models\Session;

require_once 'src/models/session.php';

interface SessionRepository
{
  public function findById(string $id): ?Session;
  public function findByCode(string $code): ?Session;
  public function findByRefreshToken(string $token): ?Session;

  public function createPending(
    string $client_id,
    string $state,
    string $nonce,
    string $session_state,
    string $redirect_uri
  ): ?Session;

  public function setAuthenticated(
    string $id,
    string $user_id,
    string $code
  ): bool;

  public function setActive(
    string $id,
    string $refresh_token
  ): bool;

  public function setExpired(
    string $id
  ): bool;

  public function updateRefreshToken(
    string $id,
    string $refresh_token
  ): bool;
}
