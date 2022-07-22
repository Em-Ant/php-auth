<?php

namespace AuthServer\Middleware;

use AuthServer\Interfaces\RealmRepository;
use AuthServer\Lib\Utils;

require_once 'src/lib/utils.php';


class RealmProvider
{
  private RealmRepository $realms;

  function __construct(RealmRepository $repo)
  {
    $this->realms = $repo;
  }

  function provide_realm(array &$ctx): void
  {
    $params = $ctx['params'] ?: [];
    $realm_name = $params['realm'];

    $realm = $this->realms->find_by_name($realm_name);
    $ctx['realm'] = $realm;

    if (!$realm) {
      Utils::server_error('not found', 'realm not found', 404);
    }
  }
}
