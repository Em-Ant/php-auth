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

$app->route('ALL', null, [Lib\Utils::class, 'enable_cors']);
$app->route('ALL', null, [Lib\Utils::class, 'parse_json_body']);

$app->route('GET', '/authorize', [$authController, 'auth']);

$app->route('ALL', '/', [Lib\Utils::class, 'not_found']);
$app->route('ALL', '/{unknown}', [Lib\Utils::class, 'not_found']);

$app->run();
