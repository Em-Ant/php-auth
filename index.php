<?php

namespace AuthServer;

use AuthServer\Controllers;
use AuthServer\Lib;
use AuthServer\Lib\Router;
use AuthServer\Repositories\DataSource;
use AuthServer\Repositories\ClientRepository;
use AuthServer\Repositories\SessionRepository;
use AuthServer\Services\AuthorizeService;

require_once 'src/lib/router.php';
require_once 'src/lib/utils.php';
require_once 'src/controllers/authorize.php';
require_once 'src/repositories/datasource.php';
require_once 'src/repositories/client_repository.php';
require_once 'src/repositories/session_repository.php';
require_once 'src/services/authorize_service.php';


$client_repo = new ClientRepository(DataSource::getInstance());
$session_repo = new SessionRepository(DataSource::getInstance());
$auth_Service = new AuthorizeService($client_repo, $session_repo);
$authController = new Controllers\Authorize($auth_Service);


$app = new Router();

$app->use([Lib\Utils::class, 'enable_cors']);
$app->use([Lib\Utils::class, 'parse_json_body']);

$app->get('/authorize', [$authController, 'authorize']);
$app->post('/login-actions/authenticate', [$authController, 'login']);

$app->all('/', [Lib\Utils::class, 'not_found']);
$app->all('/{unknown}', [Lib\Utils::class, 'not_found']);

$app->run();
