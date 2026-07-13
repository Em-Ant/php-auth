<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\InvalidInputException;
use AuthServer\Interfaces\LoginRepository as ILoginRepo;
use AuthServer\Interfaces\LoginStateMachine as ILoginStateMachine;
use AuthServer\Models\Login;
use AuthServer\Models\LoginEvent;
use AuthServer\Models\LoginStatus;
use AuthServer\Models\Realm;
use Psr\Log\LoggerInterface;

class LoginStateMachine implements ILoginStateMachine
{
    public function __construct(
        private readonly ILoginRepo $loginRepository,
        private readonly LoggerInterface $logger,
    ) {
    }

    public function transition(Login $login, LoginEvent $event, Realm $realm, array $context = []): Login
    {
        return match ($event) {
            LoginEvent::Authenticate => $this->doAuthenticate($login, $realm, $context),
            LoginEvent::Activate => $this->doActivate($login, $realm, $context),
            LoginEvent::Refresh => $this->doRefresh($login, $realm, $context),
            LoginEvent::Expire => $this->doExpire($login),
            LoginEvent::CheckExpiry => $this->doCheckExpiry($login, $realm),
        };
    }

    private function doAuthenticate(Login $login, Realm $realm, array $context): Login
    {
        $this->assertStatus($login, LoginStatus::Pending);
        $this->checkTtl($login, $realm);

        $sessionId = $context['session_id'];
        $code = $context['code'];

        $ok = $this->loginRepository->setAuthenticated(
            $login->getId(),
            $sessionId,
            $code,
        );

        if (!$ok) {
            throw new \RuntimeException('failed to authenticate login');
        }

        $updated = $this->loginRepository->findById($login->getId());
        $this->logger->info('login ' . $login->getId() . ' authenticated');

        return $updated;
    }

    private function doActivate(Login $login, Realm $realm, array $context): Login
    {
        $this->assertStatus($login, LoginStatus::Authenticated);
        $this->checkTtl($login, $realm);

        $refreshToken = $context['refresh_token'];

        $ok = $this->loginRepository->setActive(
            $login->getId(),
            $refreshToken,
        );

        if (!$ok) {
            throw new \RuntimeException('failed to activate login');
        }

        $updated = $this->loginRepository->findById($login->getId());
        $this->logger->info('login ' . $login->getId() . ' activated');

        return $updated;
    }

    private function doRefresh(Login $login, Realm $realm, array $context): Login
    {
        $this->assertStatus($login, LoginStatus::Active);
        $this->checkTtl($login, $realm);

        $newRefreshToken = $context['refresh_token'];

        $ok = $this->loginRepository->refresh(
            $login->getId(),
            $newRefreshToken,
        );

        if (!$ok) {
            throw new \RuntimeException('failed to refresh login');
        }

        $updated = $this->loginRepository->findById($login->getId());
        $this->logger->info('login ' . $login->getId() . ' refreshed');

        return $updated;
    }

    private function doExpire(Login $login): Login
    {
        if ($login->getStatus() === LoginStatus::Expired) {
            return $login;
        }

        $ok = $this->loginRepository->setExpired($login->getId());

        if (!$ok) {
            throw new \RuntimeException('failed to expire login');
        }

        $updated = $this->loginRepository->findById($login->getId());
        $this->logger->info('login ' . $login->getId() . ' expired');

        return $updated;
    }

    private function doCheckExpiry(Login $login, Realm $realm): Login
    {
        if ($login->getStatus() === LoginStatus::Expired) {
            return $login;
        }

        $expired = $this->isExpired($login, $realm);

        if ($expired) {
            return $this->doExpire($login);
        }

        return $login;
    }

    private function checkTtl(Login $login, Realm $realm): void
    {
        if ($this->isExpired($login, $realm)) {
            $this->doExpire($login);
            throw new InvalidInputException($login->getStatus()->value . ' login expired');
        }
    }

    private function isExpired(Login $login, Realm $realm): bool
    {
        $now = new \DateTime();

        return match ($login->getStatus()) {
            LoginStatus::Pending => (clone $login->getCreatedAt())->add(
                new \DateInterval('PT' . $realm->getPendingLoginExpiresIn() . 'S')
            ) < $now,
            LoginStatus::Authenticated => (clone $login->getAuthenticatedAt())->add(
                new \DateInterval('PT' . $realm->getAuthenticatedLoginExpiresIn() . 'S')
            ) < $now,
            LoginStatus::Active => (clone $login->getUpdatedAt())->add(
                new \DateInterval('PT' . $realm->getRefreshTokenExpiresIn() . 'S')
            ) < $now,
            LoginStatus::Expired => true,
        };
    }

    private function assertStatus(Login $login, LoginStatus $expected): void
    {
        if ($login->getStatus() !== $expected) {
            throw new InvalidInputException(
                'invalid login status: expected ' . $expected->value
                . ', got ' . $login->getStatus()->value
            );
        }
    }
}
