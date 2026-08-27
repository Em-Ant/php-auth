<?php

declare(strict_types=1);

namespace AuthServer\Controllers;

use AuthServer\Interfaces\KeyStore;
use AuthServer\Interfaces\UserRepository;
use AuthServer\Models\Realm;
use AuthServer\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class OidcController
{
    public function __construct(
        private readonly string $issuer,
        private readonly KeyStore $keyStore,
        private readonly UserRepository $userRepository,
    ) {
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

    /**
     * Returns the caller's claims, gated by the access token's granted scope
     * (F-41): `profile` adds the display claims, `email` the email claims,
     * `sub` is always present. Claims come from a fresh user lookup so that
     * e-mail and other sensitive values are not embedded in the access token.
     */
    public function sendUserInfo(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        /** @var array<string, mixed> $token */
        $token = $request->getAttribute('accessTokenParsed');

        $claims = ['sub' => (string) $token['sub']];
        $user = $this->userRepository->findById((string) $token['sub']);
        if ($user === null) {
            return JsonResponse::create($response, $claims, 200, '*');
        }

        $scopes = preg_split('/\s+/', trim((string) ($token['scope'] ?? ''))) ?: [];

        if (in_array('profile', $scopes, true)) {
            $claims['name'] = $user->getName();
            $claims['preferred_username'] = $user->getName();
            foreach ($this->splitName($user->getName()) as $claim => $value) {
                $claims[$claim] = $value;
            }
        }

        if (in_array('email', $scopes, true)) {
            $claims['email'] = $user->getEmail();
            $claims['email_verified'] = true;
        }

        return JsonResponse::create($response, $claims, 200, '*');
    }

    /**
     * Best-effort given/family split of a single display-name field. Returns
     * nothing when the name is a single token, so no structured name claim is
     * fabricated.
     *
     * @return array{given_name?: string, family_name?: string}
     */
    private function splitName(string $name): array
    {
        $parts = preg_split('/\s+/', trim($name));
        if ($parts === false || count($parts) < 2) {
            return [];
        }

        $given = array_shift($parts);

        return [
            'given_name' => $given,
            'family_name' => implode(' ', $parts),
        ];
    }
}
