<?php

namespace AuthServer;

use AuthServer\Controllers;
use AuthServer\Lib;
use AuthServer\Lib\Router;

require_once 'src/lib/router.php';
require_once 'src/lib/utils.php';
require_once 'src/controllers/authorize.php';

$app = new Router();

$authController = new Controllers\Authorize();

$app->route('ALL', null, 'AuthServer\Lib\Utils\enable_cors');
$app->route('ALL', null, 'AuthServer\Lib\Utils\parse_json_body');

$app->route('GET', '/authorize', array($authController, 'auth'));

$app->route('ALL', '/', 'AuthServer\Lib\Utils\api_not_found');
$app->route('ALL', '/{unknown}', 'AuthServer\Lib\Utils\api_not_found');

$app->run();
