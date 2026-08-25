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
    private AuthenticationOrchestrator $authService;
    private SessionOrchestrator $sessionOrchestrator;
    private string $mountPath;
    private SessionCookieHandler $sessionCookie;
    private ViewRenderer $view;
    private LoggerInterface $logger;

    public function __construct(
        AuthenticationOrchestrator $service,
        SessionOrchestrator $sessionOrchestrator,
        string $mountPath,
        SessionCookieHandler $sessionCookie,
        ViewRenderer $view,
        LoggerInterface $logger,
    ) {
        $this->authService = $service;
        $this->sessionOrchestrator = $sessionOrchestrator;
        $this->mountPath = $mountPath;
        $this->sessionCookie = $sessionCookie;
        $this->view = $view;
        $this->logger = $logger;
    }

    public function authorize(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        /** @var Realm */
        $realm = $request->getAttribute(Realm::class);
        $realmName = $realm->getName();
        $currentSessionId = $this->sessionCookie->read($request, $realmName);

        try {
            $query = $request->getQueryParams();
            InputValidator::validateQueryParams($query);
            $scope = $query['scope'];
            $prompt = $query['prompt'] ?? '';

            $this->authService->validateRequiredLoginScope(
                $realm,
                $query['client_id'],
                $scope
            );

            $session = null;
            if ($currentSessionId && $prompt !== 'login') {
                $session = $this->sessionOrchestrator->ensureValidSession(
                    $currentSessionId,
                    $realm->getSessionExpiresIn(),
                    $realm->getIdleSessionExpiresIn()
                );
            }

            if ($session !== null) {
                $login = $this->authService->createAuthorizedLogin(
                    $session,
                    $realm,
                    $query
                );

                $redirectUri = new RedirectUri(
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
                    ->withHeader('Location', (string) $redirectUri)
                    ->withStatus(302);
            } elseif ($prompt === 'none') {
                return $this->handlePromptNone($response, $realm, $query);
            }

            $pending = $this->authService->initializeLogin(
                $realm->getId(),
                $query
            );

            return $this->view->render($response, 'login_form.php', [
                'title' => 'Login',
                'login_id' => $pending['login_id'],
                'csrf_token' => $pending['csrf_token'],
                'realm' => $realmName,
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

        $loginId = $query['q'] ?? '';
        $csrfToken = $body['csrf_token'] ?? '';

        try {
            $this->authService->validateCsrfToken($loginId, $csrfToken);
        } catch (ValidationFailed $e) {
            return JsonResponse::error(
                $response,
                'invalid_request',
                'CSRF validation failed',
                400
            );
        }

        $result = $this->authService->ensureValidCredentials(
            $realm->getId(),
            $email,
            $password,
        );

        if ($result['error']) {
            return $this->view->render($response, 'login_form.php', [
                'title' => 'Login',
                'login_id' => $loginId,
                'csrf_token' => $csrfToken,
                'realm' => $realm->getName(),
                'email' => $email,
                'password' => $password,
                'error' => $result['error'],
            ]);
        }

        try {
            $data = $this->authService->authenticateLogin(
                $loginId,
                $result['user'],
                $realm
            );

            $sessionId = (string) $data['session']->getId();
            /** @var \AuthServer\Models\Login */
            $login = $data['login'];
            $redirectUri = new RedirectUri(
                $login->getRedirectUri(),
                $login->getResponseMode(),
                [
                    'code' => $login->getCode(),
                    'state' => $login->getState(),
                    'session_state' => $sessionId,
                ]
            );

            $response = $this->sessionCookie->write($realm, $sessionId, $response);

            return $response
                ->withHeader('Location', (string) $redirectUri)
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
            $this->authService->validateCheckSessionOrigin(
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
            $this->authService->ensureValidClient(
                $query['client_id'],
                $realm->getId(),
                $query['redirect_uri']
            );
        } catch (ValidationFailed $e) {
            return $this->redirectToError($response, $realm->getName(), $e->getMessage());
        }

        $redirectUri = new RedirectUri(
            $query['redirect_uri'],
            $query['response_mode'] ?? 'query',
            [
                'error' => 'login_required',
                'state' => $query['state'] ?? '',
            ]
        );

        return $response
            ->withHeader('Location', (string) $redirectUri)
            ->withStatus(302);
    }

    private function redirectToError(
        ResponseInterface $response,
        string $realmName,
        string $message
    ): ResponseInterface {
        $sub = $this->mountPath ?: '';
        $url = "$sub/realms/$realmName/protocol/openid-connect/error?e=" . urlencode($message);
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
