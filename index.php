<?php

namespace AuthServer;

use Emant\BrowniePhp\Router;
use Emant\BrowniePhp\Utils;
use AuthServer\Controllers;
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
use AuthServer\Lib\Logger;

require 'vendor/autoload.php';

$config = parse_ini_file('./config.ini', true);
$server = $config['server'];

$issuer = $server['issuer'];
$sub_path = $server['base_path'];

$token_service = new TokenService(
    $issuer
);

$log = $config['log'];
$logger = new Logger(
    $log['level'],
    $log['print'],
    $log['write'],
    date('Y-m-d') . '_' . $log['file'],
    __DIR__ . '/log'
);

$logHttpRequest = function () use ($logger) {
    $method = $_SERVER['REQUEST_METHOD'];
    $uri = $_SERVER['REQUEST_URI'];
    $protocol = $_SERVER['SERVER_PROTOCOL'];

    $logMessage = "$method $uri $protocol";

    $logger->info($logMessage);
};

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

$check_3rd_party_cookies = function (array $ctx) {
    $params = $ctx['params'];
    include("./src/views/3p-{$params['step']}");
    die();
};

$send_login_iframe = function () {
    include('./src/views/login-iframe.html');
    die();
};

$auth = new Router();

$auth->use([$realm_provider, 'provideRealm']);
$auth->get('/auth', [$auth_controller, 'authorize']);
$auth->post('/login-actions/authenticate', [$auth_controller, 'login']);
$auth->post(
    '/token',
    [Router::class, 'parse_basic_auth'],
    [$auth_controller, 'token']
);
$auth->get('/logout', [$auth_controller, 'logout']);
$auth->get('/error', [$auth_controller, 'error']);
$auth->get('/certs', [$auth_controller, 'sendKeys']);
$auth->get(
    '/userinfo',
    [$auth_controller, 'validateAccessTokenMiddleware'],
    [$auth_controller, 'sendUserInfo']
);
$auth->get('/3p-cookies/{step}', $check_3rd_party_cookies);
$auth->get('/login-status-iframe.html', $send_login_iframe);
$auth->get('/login-status-iframe.html/init', [Utils::class, 'ok']);

$app = new Router();

$app->use('/admin', function () {
    include('./db_admin/index.php');
    die();
});
$app->use($logHttpRequest);
$app->use('/public', Router::static_server('./public'));
$app->use([Router::class, 'parse_json_body']);
$app->use('/realms/{realm}/protocol/openid-connect', [$auth, 'run']);
$app->get(
    '/realms/{realm}/.well-known/openid-configuration',
    [$auth_controller, 'sendConfig']
);
$app->all('/', [Utils::class, 'not_found']);
$app->all('/{unknown}', [Utils::class, 'not_found']);

$app->run();
