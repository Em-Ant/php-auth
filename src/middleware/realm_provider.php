<?php

namespace AuthServer\Middleware;

use AuthServer\Interfaces\RealmRepository;
use Emant\BrowniePhp\Utils;

class RealmProvider
{
    private RealmRepository $realms;

    public function __construct(RealmRepository $repo)
    {
        $this->realms = $repo;
    }

    public function provide_realm(array &$ctx): void
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
