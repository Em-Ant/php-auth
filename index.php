<?php

namespace AuthServer;

use AuthServer\Controllers;
use AuthServer\Controllers\Authorize;
use AuthServer\Lib;
use AuthServer\Lib\Logger;
use AuthServer\Lib\Router;
use AuthServer\Middleware\RealmProvider;
use AuthServer\Middleware\SessionProvider;
use AuthServer\Repositories\DataSource;
use AuthServer\Repositories\ClientRepository;
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
require_once 'src/repositories/user_repository.php';
require_once 'src/repositories/realm_repository.php';
require_once 'src/services/authorize_service.php';
require_once 'src/services/secrets_service.php';
require_once 'src/services/token_service.php';
require_once 'src/middleware/session_provider.php';
require_once 'src/middleware/realm_provider.php';



$config = parse_ini_file('./config.ini', true);
$issuer = $config['issuer'] . '/realms/web';
$sub_path = $config['base_path'];

$client_repo = new ClientRepository(DataSource::getInstance());
$session_repo = new SessionRepository(DataSource::getInstance());
$user_repo = new UserRepository(DataSource::getInstance());
$realm_repo = new RealmRepository(DataSource::getInstance());
$realm_provider = new RealmProvider($realm_repo);
$session_provider = new SessionProvider($session_repo);

/*
$logger = new Logger();
$secrets_service = new SecretsService();



$token_service = new TokenService(
  $keys_id,
  $issuer
);

$expiration_config = [
  'pending_session_expires_in_seconds' => $env['PENDING_SESSION_EXPIRES_IN'],
  'authenticated_session_expires_in_seconds' => $env['AUTHENTICATED_SESSION_EXPIRES_IN'],
  'access_token_expires_in_seconds' => $env['ACCESS_TOKEN_EXPIRES_IN'],
  'refresh_token_expires_in_seconds' => $env['REFRESH_TOKEN_EXPIRES_IN']
];
*/

$auth_service = new AuthorizeService(
  /* $client_repo,
  $session_repo,
  $user_repo,
  $secrets_service,
  $token_service,
  $expiration_config,
  $logger */);

$auth_controller = new Controllers\Authorize($auth_service);


$auth = new Router();

$auth->use([$realm_provider, 'provide_realm']);
$auth->get(
  '/auth',
  [$session_provider, 'provide_session'],
  [$auth_controller, 'test']
);
/*
$auth->post(
  '/token',
  [Router::class, 'parse_basic_auth'],
  [$auth_controller, 'token']
);
$auth->get('/logout', [$auth_controller, 'logout']);
$auth->get('/error', [$auth_controller, 'error']);
$auth->post('/login-actions/authenticate', [$auth_controller, 'login']);
*/
$auth->get('/certs', [Authorize::class, 'send_keys']);

$app = new Router();

$app->use([Router::class, 'parse_json_body']);
$app->use('/realms/{realm}/protocol/openid-connect', [$auth, 'run']);
$app->get(
  '/realms/web/.well-known/openid-configuration',
  Authorize::send_config($issuer)
);
$app->all('/', [Lib\Utils::class, 'not_found']);
$app->all('/{unknown}', [Lib\Utils::class, 'not_found']);

$app->run();
