<?php

declare(strict_types=1);

namespace AuthServer\Controllers;

use AuthServer\Exceptions\AuthenticationFailed;
use AuthServer\Exceptions\OAuth2Error;
use AuthServer\Exceptions\StorageFailed;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\SessionCookieHandler;
use AuthServer\Models\Realm;
use AuthServer\Models\RedirectUri;
use AuthServer\Response\JsonResponse;
use AuthServer\Services\AuthenticationOrchestrator;
use AuthServer\Services\InputValidator;
use AuthServer\Services\SessionOrchestrator;
use AuthServer\Services\ViewRenderer;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;

class AuthorizationController
{
    private AuthenticationOrchestrator $auth_service;
    private SessionOrchestrator $sessionOrchestrator;
    private string $mount_path;
    private SessionCookieHandler $sessionCookie;
    private ViewRenderer $view;
    private LoggerInterface $logger;

    public function __construct(
        AuthenticationOrchestrator $service,
        SessionOrchestrator $sessionOrchestrator,
        string $mount_path,
        SessionCookieHandler $sessionCookie,
        ViewRenderer $view,
        LoggerInterface $logger,
    ) {
        $this->auth_service = $service;
        $this->sessionOrchestrator = $sessionOrchestrator;
        $this->mount_path = $mount_path;
        $this->sessionCookie = $sessionCookie;
        $this->view = $view;
        $this->logger = $logger;
    }

    public function authorize(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        /** @var Realm */
        $realm = $request->getAttribute(Realm::class);
        $realm_name = $realm->getName();
        $current_session_id = $this->sessionCookie->read($request, $realm_name);

        try {
            $query = $request->getQueryParams();
            InputValidator::validateQueryParams($query);
            $scope = $query['scope'];
            $prompt = $query['prompt'] ?? '';

            $this->auth_service->validateRequiredLoginScope(
                $realm,
                $query['client_id'],
                $scope
            );

            $session = null;
            if ($current_session_id && $prompt !== 'login') {
                $session = $this->sessionOrchestrator->ensureValidSession(
                    $current_session_id,
                    $realm->getSessionExpiresIn(),
                    $realm->getIdleSessionExpiresIn()
                );
            }

            if ($session !== null) {
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
                return $this->handlePromptNone($response, $realm, $query);
            }

            $pending = $this->auth_service->initializeLogin(
                $realm->getId(),
                $query
            );

            return $this->view->render($response, 'login_form.php', [
                'title' => 'Login',
                'login_id' => $pending['login_id'],
                'csrf_token' => $pending['csrf_token'],
                'realm' => $realm_name,
                'email' => '',
                'password' => '',
                'error' => false,
            ]);
        } catch (OAuth2Error $e) {
            return JsonResponse::errorFromOAuth2Error($response, $e);
        } catch (ValidationFailed | AuthenticationFailed $e) {
            return JsonResponse::invalidRequest($response, $e);
        } catch (StorageFailed $e) {
            return $this->redirectStorageFailure($response, $realm, $e);
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
        } catch (ValidationFailed $e) {
            return JsonResponse::error(
                $response,
                'invalid_request',
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
            return $this->view->render($response, 'login_form.php', [
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
        } catch (AuthenticationFailed $e) {
            return $this->redirectToError($response, $realm->getName(), $e->getMessage());
        } catch (StorageFailed $e) {
            return $this->redirectStorageFailure($response, $realm, $e);
        }
    }

    public function loginStatusInit(
        ServerRequestInterface $request,
        ResponseInterface $response
    ): ResponseInterface {
        $query = $request->getQueryParams();
        /** @var Realm */
        $realm = $request->getAttribute(Realm::class);

        try {
            $this->auth_service->validateCheckSessionOrigin(
                $realm,
                $query['client_id'] ?? '',
                $query['origin'] ?? ''
            );
        } catch (ValidationFailed) {
            return $response->withStatus(400);
        }

        return $response->withStatus(200);
    }

    private function handlePromptNone(
        ResponseInterface $response,
        Realm $realm,
        array $query
    ): ResponseInterface {
        try {
            $this->auth_service->ensureValidClient(
                $query['client_id'],
                $realm->getId(),
                $query['redirect_uri']
            );
        } catch (ValidationFailed $e) {
            return $this->redirectToError($response, $realm->getName(), $e->getMessage());
        }

        $redirect_uri = new RedirectUri(
            $query['redirect_uri'],
            $query['response_mode'] ?? 'query',
            [
                'error' => 'login_required',
                'state' => $query['state'] ?? '',
            ]
        );

        return $response
            ->withHeader('Location', (string) $redirect_uri)
            ->withStatus(302);
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

    private function redirectStorageFailure(
        ResponseInterface $response,
        Realm $realm,
        StorageFailed $e
    ): ResponseInterface {
        $this->logger->error('storage failure: ' . $e->getMessage(), [
            'exception' => $e,
        ]);
        return $this->redirectToError($response, $realm->getName(), $e->getMessage());
    }
}
