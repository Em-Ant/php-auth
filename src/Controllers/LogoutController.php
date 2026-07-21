<?php

declare(strict_types=1);

namespace AuthServer\Controllers;

use AuthServer\Exceptions\AuthenticationFailed;
use AuthServer\Exceptions\StorageFailed;
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
        $redirect = $query['post_logout_redirect_uri'] ?? '';
        $id_token = $query['id_token_hint'] ?? '';

        try {
            $this->auth_service->logout($id_token, $realm);
            $response = $this->sessionCookie->delete($realm, $response);
            return $response
                ->withHeader('Location', $redirect)
                ->withStatus(302);
        } catch (ValidationFailed | AuthenticationFailed $e) {
            return JsonResponse::error(
                $response,
                self::INVALID_REQUEST,
                $e->getMessage(),
                400
            );
        } catch (StorageFailed $e) {
            return JsonResponse::error(
                $response,
                self::INVALID_REQUEST,
                $e->getMessage(),
                500
            );
        }
    }
}
