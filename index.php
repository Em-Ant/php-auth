<?php

namespace AuthServer;

use AuthServer\Controllers;
use AuthServer\Lib;
use AuthServer\Lib\Logger;
use AuthServer\Lib\Router;
use AuthServer\Middleware\RealmProvider;
use AuthServer\Repositories\DataSource;
use AuthServer\Repositories\ClientRepository;
use AuthServer\Repositories\LoginRepository;
use AuthServer\Repositories\RealmRepository;
use AuthServer\Repositories\SessionRepository;
use AuthServer\Repositories\UserRepository;
use AuthServer\Services\AuthorizeService;
use AuthServer\Services\SecretsService;
use AuthServer\Services\TokenService;

require_once 'src/lib/router.php';
require_once 'src/lib/utils.php';
require_once 'src/lib/logger.php';
require_once 'src/controllers/authorize.php';
require_once 'src/repositories/data_source.php';
require_once 'src/repositories/client_repository.php';
require_once 'src/repositories/session_repository.php';
require_once 'src/repositories/login_repository.php';
require_once 'src/repositories/user_repository.php';
require_once 'src/repositories/realm_repository.php';
require_once 'src/services/authorize_service.php';
require_once 'src/services/secrets_service.php';
require_once 'src/services/token_service.php';
require_once 'src/middleware/realm_provider.php';


$config = parse_ini_file('./config.ini', true);
$server = $config['server'];

$issuer = $server['issuer'] . '/realms/web';
$sub_path = $server['base_path'];

$token_service = new TokenService(
  $issuer
);

$log = $config['log'];
$logger = new Logger(
  $log['level'],
  $log['print'],
  $log['write'],
  $log['file'],
  __DIR__
);

$secrets_service = new SecretsService();

$client_repo = new ClientRepository(DataSource::getInstance());
$session_repo = new SessionRepository(DataSource::getInstance());
$login_repo = new LoginRepository(DataSource::getInstance());
$user_repo = new UserRepository(DataSource::getInstance());
$realm_repo = new RealmRepository(DataSource::getInstance());
$realm_provider = new RealmProvider($realm_repo);

$auth_service = new AuthorizeService(
  $client_repo,
  $session_repo,
  $user_repo,
  $login_repo,
  $secrets_service,
  $token_service,
  $logger
);

$auth_controller = new Controllers\Authorize(
  $auth_service,
  $issuer,
  $sub_path
);


$auth = new Router();

$auth->use([$realm_provider, 'provide_realm']);
$auth->get('/auth', [$auth_controller, 'authorize']);
$auth->post('/login-actions/authenticate', [$auth_controller, 'login']);
$auth->post(
  '/token',
  [Router::class, 'parse_basic_auth'],
  [$auth_controller, 'token']
);
$auth->get('/logout', [$auth_controller, 'logout']);
$auth->get('/error', [$auth_controller, 'error']);
$auth->get('/certs', [$auth_controller, 'send_keys']);


$app = new Router();

$app->use([Router::class, 'parse_json_body']);
$app->use('/realms/{realm}/protocol/openid-connect', [$auth, 'run']);
$app->get(
  '/realms/web/.well-known/openid-configuration',
  [$auth_controller, 'send_config']
);
$app->all('/', [Lib\Utils::class, 'not_found']);
$app->all('/{unknown}', [Lib\Utils::class, 'not_found']);

$app->run();
