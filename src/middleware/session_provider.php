<?php

namespace AuthServer\Middleware;

use AuthServer\Interfaces\SessionRepository;
use AuthServer\Lib\Utils;

class SessionProvider
{
  private SessionRepository $sessions;

  function __construct(SessionRepository $repo)
  {
    $this->sessions = $repo;
  }

  function provide_session(array &$ctx): void
  {
    $session_cookie = $_COOKIE['AUTH_SESSION'];

    if (!$ctx['realm']) {
      Utils::server_error(
        'internal server error',
        'realm data not available',
        500
      );
    }
    if (!$session_cookie) {
      return;
    }

    $parts = explode('\\', $session_cookie);
    $realm_name = $parts[0];
    $session_id = $parts[1];

    if ($realm_name != $ctx['realm']['name']) {
      return;
    }

    $session = $this->sessions->find_by_id($session_id);
    $ctx['session'] = $session;
  }
}
