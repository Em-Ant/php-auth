<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Interfaces\UserRepository;

/**
 * Builds the /userinfo claims for an access token, gated by its granted
 * scope (F-41): `profile` adds the display claims, `email` the email claims,
 * `sub` is always present. Claims come from a fresh user lookup so that
 * e-mail and other sensitive values are not embedded in the access token.
 */
class UserInfoService
{
    public function __construct(
        private readonly UserRepository $users,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function getUserInfo(string $userId, string $scope): array
    {
        $claims = ['sub' => $userId];
        $user = $this->users->findById($userId);
        if ($user === null) {
            return $claims;
        }

        $scopes = preg_split('/\s+/', trim($scope)) ?: [];

        if (in_array('profile', $scopes, true)) {
            $claims['name'] = $user->getName();
            $claims['preferred_username'] = $user->getName();
            foreach ($this->splitName($user->getName()) as $claim => $value) {
                $claims[$claim] = $value;
            }
        }

        if (in_array('email', $scopes, true)) {
            $claims['email'] = $user->getEmail();
            $claims['email_verified'] = $user->getEmailVerified();
        }

        return $claims;
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
