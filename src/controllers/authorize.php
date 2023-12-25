<?php

declare(strict_types=1);

namespace AuthServer\Controllers;

use AuthServer\Exceptions\CriticalLoginErrorException;
use Emant\BrowniePhp\Utils;
use AuthServer\Exceptions\InvalidInputException;
use AuthServer\Models\Login;
use AuthServer\Models\Realm;
use AuthServer\Services\AuthorizeService;

class Authorize
{
    private AuthorizeService $auth_service;
    private string $issuer;
    private string $mount_path;

    public const INVALID_REQUEST = 'Invalid request';
    public const INVALID_TOKEN = 'Invalid token';


    public function __construct(
        AuthorizeService $service,
        string $issuer,
        string $mount_path
    ) {
        $this->auth_service = $service;
        $this->issuer = $issuer;
        $this->mount_path = $mount_path;
    }

    public function authorize(array $ctx)
    {
        /** @var Realm */
        $realm = $ctx['realm'];

        $realm_name = $realm->getName();
        $current_session_id =
            self::getSessionIdFromCookie($realm_name);

        try {
            $query = $ctx['query'];
            $scope = $query['scope'];
            $prompt = $query['prompt'] ?? '';

            $this->auth_service->validateRequiredLoginScope(
                $realm->getScope(),
                $scope
            );

            if ($current_session_id) {
                $session = $this->auth_service->ensureValidSession(
                    $current_session_id,
                    $realm->getSessionExpiresIn(),
                    $realm->getIdleSessionExpiresIn()
                );
            }

            if (isset($session) && $session != null) {
                $login = $this->auth_service->createAuthorizedLogin(
                    $session,
                    $query
                );

                $redirect_uri = self::getRedirectUri($login, $session->getId());

                $this->setSessionCookie($realm, $current_session_id);
                header("location: $redirect_uri", true, 302);
                die();
            } elseif ($prompt === 'none') {
                $redirect_uri = self::getLoginRequiredRedirectUri(
                    $query['redirect_uri'],
                    $query['response_mode'],
                    $query['state']
                );
                header("location: $redirect_uri", true, 302);
                die();
            } else {
                $pending_login_id = $this->auth_service->initializeLogin(
                    $query
                );
                Utils::show_view(
                    'login_form',
                    [
                        'title' => 'Login',
                        'login_id' => $pending_login_id,
                        'realm' => $realm_name,
                        'email' => '',
                        'password' => '',
                        'error' => false
                    ]
                );
                die();
            }
        } catch (InvalidInputException $e) {
            Utils::server_error(self::INVALID_REQUEST, $e->getMessage(), 400);
        } catch (CriticalLoginErrorException $e) {
            $this->redirectToError($realm->getName(), $e->getMessage());
        }
    }

    public function login(array $ctx)
    {
        $query = $ctx['query'];
        $body = $ctx['body'];

        /** @var Realm */
        $realm = $ctx['realm'];

        $email = $body['email'];
        $password = $body['password'];

        $login_id = $query['q'];

        $result = $this->auth_service->ensureValidCredentials(
            $email,
            $password,
        );
        if ($result['error']) {
            Utils::show_view(
                'login_form',
                [
                    'title' => 'Login',
                    'login_id' => $login_id,
                    'realm' => $realm->getName(),
                    'email' => $email,
                    'password' => $password,
                    'error' => $result['error']
                ]
            );
            die();
        }

        try {
            $data = $this->auth_service->authenticateLogin(
                $login_id,
                $result['user'],
                $realm
            );

            $session_id = (string) $data['session']->getId();
            /** @var Login */
            $login = $data['login'];
            $redirect_uri = self::getRedirectUri($login, $session_id);

            $this->setSessionCookie($realm, $session_id);

            header("location: $redirect_uri", true, 302);
            die();
        } catch (CriticalLoginErrorException $e) {
            $this->redirectToError($realm->getName(), $e->getMessage());
        }
    }

    public function token(array $ctx)
    {
        $body = $ctx['body'];
        if (!isset($body['client_id'])) {
            $body['client_id'] = isset($ctx['basic_auth_user'])
                ? $ctx['basic_auth_user']
                : null;
        }

        if (!isset($body['client_secret'])) {
            $body['client_secret'] = isset($ctx['basic_auth_pwd'])
                ? $ctx['basic_auth_pwd']
                : null;
        }

        try {
            $realm = $ctx['realm'];
            $headers = $ctx['headers'];
            $origin = $headers['origin'] ??
                $this->auth_service->getClientUri($body['client_id']);
            Utils::enable_cors($origin);
            Utils::send_json($this->auth_service->getTokens($body, $realm));
        } catch (InvalidInputException $e) {
            Utils::server_error(self::INVALID_REQUEST, $e->getMessage(), 400);
        }
    }

    public function error(array $ctx)
    {
        $message = $ctx['query']['e'];
        Utils::show_view('error', [
            'title' => 'Error',
            'error' => $message
        ]);
    }

    public function logout(array $ctx)
    {
        /** @var Realm */
        $realm = $ctx['realm'];
        $query = $ctx['query'];
        $redirect = $query['post_logout_redirect_uri'];
        $id_token = $query['id_token_hint'];
        try {
            $this->auth_service->logout($id_token, $realm);
            $this->deleteSessionCookie($realm);
            header("location: $redirect", true, 302);
            die();
        } catch (InvalidInputException $e) {
            Utils::server_error(self::INVALID_REQUEST, $e->getMessage(), 400);
        }
    }

    public function sendKeys(array $ctx)
    {
        /** @var Realm */
        $realm = $ctx['realm'];
        $kid = $realm->getKeysId();
        $keys = file_get_contents("keys/$kid/keys.json", true);
        header('Content-Type: application/json; charset=utf-8');
        Utils::enable_cors();
        echo $keys;
        die();
    }

    public function sendConfig()
    {
        $data = file_get_contents('./static/well-known.json', true);
        header('Content-Type: application/json; charset=utf-8');
        Utils::enable_cors();
        echo str_replace('<<ISSUER>>', $this->issuer, $data);
        die();
    }

    private static function getSessionIdFromCookie(
        string $realm_name
    ): ?string {
        $session_cookie = isset($_COOKIE['AUTH_SESSION'])
            ? $_COOKIE['AUTH_SESSION']
            : null;

        if (!$session_cookie) {
            return null;
        }

        $parts = explode('\\', $session_cookie);
        $cookie_realm_name = $parts[0];
        $session_id = $parts[1];

        if ($realm_name != $cookie_realm_name) {
            return null;
        }

        return $session_id;
    }

    private function setSessionCookie(
        Realm $realm,
        string $session_id
    ) {
        $realm_name = $realm->getName();
        $mount_path = $this->mount_path ?: '';

        setcookie('AUTH_SESSION', "$realm_name\\$session_id", [
            'expires' => time() + $realm->getSessionExpiresIn(),
            'path' => "$mount_path/realms/$realm_name",
            'domain' => $_SERVER['SERVER_NAME'],
            'httponly' => false,
            'secure' => true,
            'samesite' => 'None',
        ]);
    }


    private function deleteSessionCookie(Realm $realm)
    {
        $realm_name = $realm->getName();
        $mount_path = $this->mount_path ?: '';

        setcookie('AUTH_SESSION', "", [
            'expires' => 1,
            'path' => "$mount_path/realms/$realm_name",
            'domain' => $_SERVER['SERVER_NAME'],
            'httponly' => true,
            'secure' => true,
            'samesite' => 'None',
        ]);
    }

    private static function getLoginRequiredRedirectUri(
        string $redirect_uri,
        string $response_mode,
        string $state
    ) {
        $char = '';
        $append = '';
        $hash_pos = strpos($redirect_uri, '#');

        if ($response_mode == 'query') {
            $char = strpos($redirect_uri, '?') ? '&' : '?';
            if ($hash_pos) {
                $append = substr($redirect_uri, $hash_pos);
                $redirect_uri = substr($redirect_uri, 0, $hash_pos);
            }
        } else {
            $char = $hash_pos ? '&' : '#';
        }

        return $redirect_uri . $char .
            'error=login_required' .
            '&state=' . $state .
            $append;
    }

    private static function getRedirectUri(
        Login $login,
        string $session_id
    ): string {
        $redirect_uri = $login->getRedirectUri();
        $response_mode = $login->getResponseMode();
        $append = '';
        $char = '';
        $hash_pos = strpos($redirect_uri, '#');

        if ($response_mode == 'query') {
            $char = strpos($redirect_uri, '?') ? '&' : '?';
            if ($hash_pos) {
                $append = substr($redirect_uri, $hash_pos);
                $redirect_uri = substr($redirect_uri, 0, $hash_pos);
            }
        } else {
            $char = $hash_pos ? '&' : '#';
        }

        return $redirect_uri . $char .
            'code=' . $login->getCode() .
            '&state=' . $login->getState() .
            '&session_state=' . $session_id .
            $append;
    }

    private function redirectToError($realm_name, $message)
    {
        $sub = $this->mount_path ?: '';
        header(
            "location: $sub/realms/$realm_name/protocol/openid-connect/error?e=$message",
            true,
            302
        );
        die();
    }

    public function validateAccessTokenMiddleware(array &$ctx)
    {
        /** @var Realm */
        $realm = $ctx['realm'];

        $token = '';
        if (array_key_exists('authorization', $ctx['headers'])) {
            $token = str_replace('Bearer ', '', $ctx['headers']['authorization']);
        }

        try {
            $ctx['accessTokenParsed'] = $this->auth_service->parseValidToken($token, $realm);
        } catch (InvalidInputException $e) {
            Utils::server_error(self::INVALID_REQUEST, $e->getMessage(), 400);
        }
    }

    public function sendUserInfo(array $ctx)
    {
        $token = $ctx['accessTokenParsed'];
        $user = [];
        $user['sub'] = $token['sub'];
        $user['preferred_username'] = $token['preferred_username'];
        Utils::send_json($user);
    }
}
