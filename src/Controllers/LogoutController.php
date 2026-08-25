<?php

declare(strict_types=1);

namespace AuthServer\Controllers;

use AuthServer\Exceptions\AuthenticationFailed;
use AuthServer\Exceptions\OAuth2Error;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\SessionCookieHandler;
use AuthServer\Models\Realm;
use AuthServer\Response\JsonResponse;
use AuthServer\Services\AuthenticationOrchestrator;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class LogoutController
{
    private AuthenticationOrchestrator $authService;
    private SessionCookieHandler $sessionCookie;

    public function __construct(
        AuthenticationOrchestrator $service,
        SessionCookieHandler $sessionCookie,
    ) {
        $this->authService = $service;
        $this->sessionCookie = $sessionCookie;
    }

    public function logout(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        /** @var Realm */
        $realm = $request->getAttribute(Realm::class);
        $query = $request->getQueryParams();
        $postLogoutRedirectUri = $query['post_logout_redirect_uri'] ?? '';
        $idToken = $query['id_token_hint'] ?? '';

        try {
            if ($idToken === '') {
                $response = $this->sessionCookie->delete($realm, $response);
                return $response->withStatus(204);
            }

            $this->authService->logout($idToken, $realm);
            $response = $this->sessionCookie->delete($realm, $response);

            $redirectUri = $this->authService->validateLogoutRedirectUri(
                $idToken,
                $postLogoutRedirectUri
            );
            if ($redirectUri === null) {
                return $response->withStatus(204);
            }

            return $response
                ->withHeader('Location', $redirectUri)
                ->withStatus(302);
        } catch (OAuth2Error $e) {
            return JsonResponse::errorFromOAuth2Error($response, $e);
        } catch (ValidationFailed | AuthenticationFailed $e) {
            return JsonResponse::invalidRequest($response, $e);
        }
    }
}
