<?php

declare(strict_types=1);

namespace AuthServer\Controllers;

use AuthServer\Exceptions\AuthenticationFailed;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\SessionCookieHandler;
use AuthServer\Models\Realm;
use AuthServer\Response\JsonResponse;
use AuthServer\Services\AuthenticationOrchestrator;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class LogoutController
{
    private AuthenticationOrchestrator $auth_service;
    private SessionCookieHandler $sessionCookie;

    public const INVALID_REQUEST = 'Invalid request';

    public function __construct(
        AuthenticationOrchestrator $service,
        SessionCookieHandler $sessionCookie,
    ) {
        $this->auth_service = $service;
        $this->sessionCookie = $sessionCookie;
    }

    public function logout(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        /** @var Realm */
        $realm = $request->getAttribute(Realm::class);
        $query = $request->getQueryParams();
        $post_logout_redirect_uri = $query['post_logout_redirect_uri'] ?? '';
        $id_token = $query['id_token_hint'] ?? '';

        try {
            if ($id_token === '') {
                $response = $this->sessionCookie->delete($realm, $response);
                return $response->withStatus(204);
            }

            $this->auth_service->logout($id_token, $realm);
            $response = $this->sessionCookie->delete($realm, $response);

            $redirect_uri = $this->auth_service->validateLogoutRedirectUri(
                $id_token,
                $post_logout_redirect_uri
            );
            if ($redirect_uri === null) {
                return $response->withStatus(204);
            }

            return $response
                ->withHeader('Location', $redirect_uri)
                ->withStatus(302);
        } catch (ValidationFailed | AuthenticationFailed $e) {
            return JsonResponse::error(
                $response,
                self::INVALID_REQUEST,
                $e->getMessage(),
                400
            );
        }
    }
}
