<?php

namespace AuthServer;

use AuthServer\Controllers;
use AuthServer\Lib;
use AuthServer\Lib\Router;
use AuthServer\Lib\Utils;
use AuthServer\Repositories\DataSource;
use AuthServer\Repositories\ClientRepository;
use AuthServer\Repositories\SessionRepository;
use AuthServer\Repositories\UserRepository;
use AuthServer\Services\AuthorizeService;
use AuthServer\Services\SecretsService;
use AuthServer\Services\TokenService;

require_once 'src/lib/router.php';
require_once 'src/lib/utils.php';
require_once 'src/controllers/authorize.php';
require_once 'src/repositories/datasource.php';
require_once 'src/repositories/client_repository.php';
require_once 'src/repositories/session_repository.php';
require_once 'src/repositories/user_repository.php';
require_once 'src/services/authorize_service.php';
require_once 'src/services/secrets_service.php';
require_once 'src/services/token_service.php';

$env = Utils::read_env('server.env');
$sub_path = $env['BASE_PATH'];
$pub = file_get_contents('keys/public_key.pem');
$pri = file_get_contents('keys/private_key.pem');

$client_repo = new ClientRepository(DataSource::getInstance());
$session_repo = new SessionRepository(DataSource::getInstance());
$user_repo = new UserRepository(DataSource::getInstance());

$secrets_service = new SecretsService();

$token_service = new TokenService(
  $pub,
  $pri,
  '1',
  'emant/auth',
  $env['REFRESH_TOKEN_EXPIRES_IN'],
  $env['ACCESS_TOKEN_EXPIRES_IN'],
);

$auth_service = new AuthorizeService(
  $client_repo,
  $session_repo,
  $user_repo,
  $secrets_service,
  $token_service,
  $env['PENDING_SESSION_EXPIRES_IN'],
  $env['AUTHENTICATED_SESSION_EXPIRES_IN']
);

$auth_controller = new Controllers\Authorize($auth_service);


$app = new Router();

$app->use([Lib\Utils::class, 'enable_cors']);
$app->use([Lib\Utils::class, 'parse_json_body']);

$app->get('/authorize', [$auth_controller, 'authorize']);
$app->post('/token', [$auth_controller, 'token']);
$app->get('/error', [$auth_controller, 'error']);
$app->post('/login-actions/authenticate', [$auth_controller, 'login']);

$app->all('/', [Lib\Utils::class, 'not_found']);
$app->all('/{unknown}', [Lib\Utils::class, 'not_found']);

$app->run();
