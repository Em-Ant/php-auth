<?php

namespace AuthServer\Interfaces;

use AuthServer\Models\Session;

require_once 'src/models/session.php';

interface SessionRepository
{
  public function findById(string $id): ?Session;
  public function findByCode(string $code): ?Session;

  public function createPending(
    string $client_id,
    string $state,
    string $nonce,
    string $redirect_uri
  ): ?Session;

  public function updateWithUserIdAndCode(
    string $id,
    string $user_id,
    string $code
  ): ?Session;

  public function updateWithRefreshToken(
    string $id,
    string $refresh_token
  ): ?Session;
}
