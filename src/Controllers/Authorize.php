<?php

declare(strict_types=1);

namespace AuthServer\Controllers;

use AuthServer\Exceptions\CriticalLoginErrorException;
use AuthServer\Exceptions\InvalidInputException;
use AuthServer\Interfaces\KeyStore;
use AuthServer\Interfaces\SessionCookieHandler;
use AuthServer\Models\Realm;
use AuthServer\Models\RedirectUri;
use AuthServer\Response\JsonResponse;
use AuthServer\Services\AuthorizeService;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Response;

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

    public function authorize(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        /** @var Realm */
        $realm = $request->getAttribute(Realm::class);
        $realm_name = $realm->getName();
        $current_session_id = $this->sessionCookie->read($realm_name);

        try {
            $query = $request->getQueryParams();
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

                $response = $this->sessionCookie->write($realm, $session->getId(), $response);
                return $response
                    ->withHeader('Location', (string) $redirect_uri)
                    ->withStatus(302);
            } elseif ($prompt === 'none') {
                $redirect_uri = new RedirectUri(
                    $query['redirect_uri'],
                    $query['response_mode'],
                    [
                        'error' => 'login_required',
                        'state' => $query['state'],
                    ]
                );
                return $response
                    ->withHeader('Location', (string) $redirect_uri)
                    ->withStatus(302);
            } else {
                $pending = $this->auth_service->initializeLogin(
                    $realm->getId(),
                    $query
                );

                return $this->renderView($response, 'login_form', [
                    'title' => 'Login',
                    'login_id' => $pending['login_id'],
                    'csrf_token' => $pending['csrf_token'],
                    'realm' => $realm_name,
                    'email' => '',
                    'password' => '',
                    'error' => false,
                ]);
            }
        } catch (InvalidInputException $e) {
            return JsonResponse::error(
                $response,
                self::INVALID_REQUEST,
                $e->getMessage(),
                400
            );
        } catch (CriticalLoginErrorException $e) {
            return $this->redirectToError($response, $realm->getName(), $e->getMessage());
        }
    }

    public function login(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $query = $request->getQueryParams();
        $body = $request->getParsedBody() ?? [];

        /** @var Realm */
        $realm = $request->getAttribute(Realm::class);

        $email = $body['email'] ?? '';
        $password = $body['password'] ?? '';

        $login_id = $query['q'] ?? '';
        $csrf_token = $body['csrf_token'] ?? '';

        try {
            $this->auth_service->validateCsrfToken($login_id, $csrf_token);
        } catch (InvalidInputException $e) {
            return JsonResponse::error(
                $response,
                'Invalid request',
                'CSRF validation failed',
                400
            );
        }

        $result = $this->auth_service->ensureValidCredentials(
            $realm->getId(),
            $email,
            $password,
        );

        if ($result['error']) {
            return $this->renderView($response, 'login_form', [
                'title' => 'Login',
                'login_id' => $login_id,
                'csrf_token' => $csrf_token,
                'realm' => $realm->getName(),
                'email' => $email,
                'password' => $password,
                'error' => $result['error'],
            ]);
        }

        try {
            $data = $this->auth_service->authenticateLogin(
                $login_id,
                $result['user'],
                $realm
            );

            $session_id = (string) $data['session']->getId();
            /** @var \AuthServer\Models\Login */
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

            $response = $this->sessionCookie->write($realm, $session_id, $response);

            return $response
                ->withHeader('Location', (string) $redirect_uri)
                ->withStatus(302);
        } catch (CriticalLoginErrorException $e) {
            return $this->redirectToError($response, $realm->getName(), $e->getMessage());
        }
    }

    public function token(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $body = $request->getParsedBody() ?? [];

        $authHeader = $request->getHeaderLine('Authorization');
        if (str_starts_with($authHeader, 'Basic ')) {
            $cred = explode(':', base64_decode(substr($authHeader, 6)));
            if (!isset($body['client_id'])) {
                $body['client_id'] = $cred[0] ?? null;
            }
            if (!isset($body['client_secret'])) {
                $body['client_secret'] = $cred[1] ?? null;
            }
        }

        try {
            /** @var Realm */
            $realm = $request->getAttribute(Realm::class);

            $origin = $request->getHeaderLine('Origin')
                ?: $this->auth_service->getClientUri($body['client_id'] ?? '');

            return JsonResponse::create(
                $response,
                $this->auth_service->getTokens($body, $realm),
                200,
                $origin
            );
        } catch (InvalidInputException $e) {
            return JsonResponse::error(
                $response,
                self::INVALID_REQUEST,
                $e->getMessage(),
                400
            );
        }
    }

    public function error(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $query = $request->getQueryParams();
        $message = $query['e'] ?? '';

        return $this->renderView($response, 'error', [
            'title' => 'Error',
            'error' => $message,
        ]);
    }

    public function logout(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        /** @var Realm */
        $realm = $request->getAttribute(Realm::class);
        $query = $request->getQueryParams();
        $redirect = $query['post_logout_redirect_uri'] ?? '';
        $id_token = $query['id_token_hint'] ?? '';

        try {
            $this->auth_service->logout($id_token, $realm);
            $response = $this->sessionCookie->delete($realm, $response);
            return $response
                ->withHeader('Location', $redirect)
                ->withStatus(302);
        } catch (InvalidInputException $e) {
            return JsonResponse::error(
                $response,
                self::INVALID_REQUEST,
                $e->getMessage(),
                400
            );
        }
    }

    public function sendKeys(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        /** @var Realm */
        $realm = $request->getAttribute(Realm::class);
        $kid = $realm->getKeysId();
        $keySet = $this->keyStore->findKeys($kid);

        return JsonResponse::create(
            $response,
            $keySet->jwks,
            200,
            '*'
        );
    }

    public function sendConfig(
        ServerRequestInterface $request,
        ResponseInterface $response
    ): ResponseInterface {
        $realm_name = $request->getAttribute('realm');

        $data = file_get_contents(__DIR__ . '/../../static/well-known.json');
        $data = str_replace(
            '<<ISSUER>>',
            $this->issuer . "/realms/$realm_name",
            $data
        );

        $response->getBody()->write($data);
        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Access-Control-Allow-Origin', '*');
    }

    public function validateAccessTokenMiddleware(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler
    ): ResponseInterface {
        /** @var Realm */
        $realm = $request->getAttribute(Realm::class);

        $token = '';
        $authHeader = $request->getHeaderLine('Authorization');
        if ($authHeader !== '') {
            $token = str_replace('Bearer ', '', $authHeader);
        }

        try {
            $parsed = $this->auth_service->parseValidToken($token, $realm);
            $request = $request->withAttribute('accessTokenParsed', $parsed);
            return $handler->handle($request);
        } catch (InvalidInputException $e) {
            $response = new Response();
            return JsonResponse::error(
                $response,
                self::INVALID_TOKEN,
                $e->getMessage(),
                400
            );
        }
    }

    public function sendUserInfo(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $token = $request->getAttribute('accessTokenParsed');
        $user = [];
        $user['sub'] = $token['sub'];
        $user['preferred_username'] = $token['preferred_username'];

        return JsonResponse::create($response, $user, 200, '*');
    }

    private function renderView(ResponseInterface $response, string $view, array $params): ResponseInterface
    {
        $viewFile = __DIR__ . '/../views/' . $view . '.php';
        $templateFile = __DIR__ . '/../views/template.php';

        $params['view'] = $viewFile;

        extract($params);
        unset($params);

        ob_start();
        include $templateFile;
        $html = ob_get_clean();

        $response->getBody()->write($html);
        return $response->withHeader('Content-Type', 'text/html; charset=utf-8');
    }

    private function redirectToError(
        ResponseInterface $response,
        string $realm_name,
        string $message
    ): ResponseInterface {
        $sub = $this->mount_path ?: '';
        $url = "$sub/realms/$realm_name/protocol/openid-connect/error?e=" . urlencode($message);
        return $response
            ->withHeader('Location', $url)
            ->withStatus(302);
    }
}
