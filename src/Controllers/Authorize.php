<?php

declare(strict_types=1);

namespace AuthServer\Controllers;

use AuthServer\Exceptions\CriticalLoginErrorException;
use AuthServer\Interfaces\KeyStore;
use AuthServer\Interfaces\SessionCookieHandler;
use AuthServer\Models\RedirectUri;
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
    private KeyStore $keyStore;
    private SessionCookieHandler $sessionCookie;

    public const INVALID_REQUEST = 'Invalid request';
    public const INVALID_TOKEN = 'Invalid token';


    public function __construct(
        AuthorizeService $service,
        string $issuer,
        string $mount_path,
        KeyStore $keyStore,
        SessionCookieHandler $sessionCookie,
    ) {
        $this->auth_service = $service;
        $this->issuer = $issuer;
        $this->mount_path = $mount_path;
        $this->keyStore = $keyStore;
        $this->sessionCookie = $sessionCookie;
    }

    public function authorize(array $ctx)
    {
        /** @var Realm */
        $realm = $ctx['realm'];

        $realm_name = $realm->getName();
        $current_session_id =
            $this->sessionCookie->read($realm_name);

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

            if (isset($session) && $session !== null) {
                $login = $this->auth_service->createAuthorizedLogin(
                    $session,
                    $realm,
                    $query
                );

                $redirect_uri = new RedirectUri(
                    $login->getRedirectUri(),
                    $login->getResponseMode(),
                    [
                        'code' => $login->getCode(),
                        'state' => $login->getState(),
                        'session_state' => $session->getId(),
                    ]
                );

                $this->sessionCookie->write($realm, $current_session_id);
                header("location: $redirect_uri", true, 302);
                die();
            } elseif ($prompt === 'none') {
                $redirect_uri = new RedirectUri(
                    $query['redirect_uri'],
                    $query['response_mode'],
                    [
                        'error' => 'login_required',
                        'state' => $query['state'],
                    ]
                );
                header("location: $redirect_uri", true, 302);
                die();
            } else {
                $pending = $this->auth_service->initializeLogin(
                    $realm->getId(),
                    $query
                );
                Utils::show_view(
                    'login_form',
                    [
                        'title' => 'Login',
                        'login_id' => $pending['login_id'],
                        'csrf_token' => $pending['csrf_token'],
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
        $csrf_token = $body['csrf_token'] ?? '';

        try {
            $this->auth_service->validateCsrfToken($login_id, $csrf_token);
        } catch (InvalidInputException $e) {
            Utils::server_error('Invalid request', 'CSRF validation failed', 400);
            die();
        }

        $result = $this->auth_service->ensureValidCredentials(
            $realm->getId(),
            $email,
            $password,
        );
        if ($result['error']) {
            Utils::show_view(
                'login_form',
                [
                    'title' => 'Login',
                    'login_id' => $login_id,
                    'csrf_token' => $csrf_token,
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
            $redirect_uri = new RedirectUri(
                $login->getRedirectUri(),
                $login->getResponseMode(),
                [
                    'code' => $login->getCode(),
                    'state' => $login->getState(),
                    'session_state' => $session_id,
                ]
            );

            $this->sessionCookie->write($realm, $session_id);

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
            $this->sessionCookie->delete($realm);
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
        $keySet = $this->keyStore->findKeys($kid);
        header('Content-Type: application/json; charset=utf-8');
        Utils::enable_cors();
        echo json_encode($keySet->jwks);
        die();
    }

    public function sendConfig(array $ctx)
    {
        /** @var Realm */
        $params = $ctx['params'];
        $realm_name = $params['realm'];
        $data = file_get_contents('./static/well-known.json', true);
        header('Content-Type: application/json; charset=utf-8');
        Utils::enable_cors();
        echo str_replace('<<ISSUER>>', $this->issuer . "/realms/$realm_name", $data);
        die();
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
