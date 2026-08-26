<?php

declare(strict_types=1);

namespace AuthServer\Controllers;

use AuthServer\Interfaces\KeyStore;
use AuthServer\Models\Realm;
use AuthServer\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class OidcController
{
    private string $issuer;
    private KeyStore $keyStore;

    public function __construct(
        string $issuer,
        KeyStore $keyStore,
    ) {
        $this->issuer = $issuer;
        $this->keyStore = $keyStore;
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
        /** @var Realm */
        $realm = $request->getAttribute(Realm::class);

        $data = file_get_contents(__DIR__ . '/../../static/well-known.json');
        if ($data === false) {
            $response->getBody()->write(json_encode([
                'error' => 'server_error',
                'error_description' => 'well-known.json not found',
            ]));
            return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
        }
        $data = str_replace(
            '<<ISSUER>>',
            $this->issuer . '/realms/' . $realm->getName(),
            $data
        );
        $data = str_replace(
            '<<SCOPE_SUPPORTED>>',
            (string) json_encode(array_values(array_unique(array_merge(['openid'], $realm->getScope())))),
            $data
        );

        $response->getBody()->write($data);
        return $response->withHeader('Content-Type', 'application/json');
    }

    public function sendUserInfo(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $token = $request->getAttribute('accessTokenParsed');
        $user = [];
        $user['sub'] = $token['sub'];
        $user['preferred_username'] = $token['preferred_username'];

        return JsonResponse::create($response, $user, 200, '*');
    }
}
