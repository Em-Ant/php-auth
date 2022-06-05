<?php

namespace AuthServer;

use AuthServer\Controllers;
use AuthServer\Lib;
use AuthServer\Lib\Router;
use AuthServer\Repositories\DataSource;
use AuthServer\Repositories\SQLiteClientRepository;
use AuthServer\Validators\ValidateAuthorize;

require_once 'src/lib/router.php';
require_once 'src/lib/utils.php';
require_once 'src/controllers/authorize.php';
require_once 'src/repositories/datasource.php';
require_once 'src/repositories/sqlite_client_repository.php';
require_once 'src/validators/validate_authorize.php';


$app = new Router();

$client_repo = new SQLiteClientRepository(DataSource::getInstance());
$validator = new ValidateAuthorize($client_repo);
$authController = new Controllers\Authorize($validator);

$app->use([Lib\Utils::class, 'enable_cors']);
$app->use([Lib\Utils::class, 'parse_json_body']);

$app->get('/authorize', [$authController, 'auth']);

$app->all('/', [Lib\Utils::class, 'not_found']);
$app->all('/{unknown}', [Lib\Utils::class, 'not_found']);

$app->run();
