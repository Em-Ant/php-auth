<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\LoginRepository as ILoginRepo;
use AuthServer\Models\Login;
use AuthServer\Models\LoginEvent;
use AuthServer\Models\LoginStatus;
use AuthServer\Models\Realm;
use Psr\Log\LoggerInterface;

class LoginStateMachine
{
    public function __construct(
        private ILoginRepo $loginRepository,
        private LoggerInterface $logger,
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

        if ($this->isExpired($login, $realm)) {
            $login->setStatus(LoginStatus::Expired);
            throw new ValidationFailed($login->getStatus()->value . ' login expired');
        }

        $login->setSessionId($context['session_id']);
        $login->setCode($context['code']);
        $login->setAuthenticatedAt(new \DateTime());
        $login->setUpdatedAt(new \DateTime());
        $login->setStatus(LoginStatus::Authenticated);

        $ok = $this->loginRepository->setAuthenticated(
            $login->getId(),
            $context['session_id'],
            $context['code'],
        );

        if (!$ok) {
            throw new \RuntimeException('failed to persist authenticated login');
        }

        $this->logger->info('login ' . $login->getId() . ' authenticated');
        return $login;
    }

    private function doActivate(Login $login, Realm $realm, array $context): Login
    {
        $this->assertStatus($login, LoginStatus::Authenticated);

        if ($this->isExpired($login, $realm)) {
            $login->setStatus(LoginStatus::Expired);
            throw new ValidationFailed($login->getStatus()->value . ' login expired');
        }

        $login->setRefreshToken($context['refresh_token']);
        $login->setUpdatedAt(new \DateTime());
        $login->setStatus(LoginStatus::Active);

        $ok = $this->loginRepository->setActive(
            $login->getId(),
            $context['refresh_token'],
        );

        if (!$ok) {
            throw new \RuntimeException('failed to persist activated login');
        }

        $this->logger->info('login ' . $login->getId() . ' activated');
        return $login;
    }

    private function doRefresh(Login $login, Realm $realm, array $context): Login
    {
        $this->assertStatus($login, LoginStatus::Active);

        if ($this->isExpired($login, $realm)) {
            $login->setStatus(LoginStatus::Expired);
            throw new ValidationFailed($login->getStatus()->value . ' login expired');
        }

        $login->setRefreshToken($context['refresh_token']);
        $login->setUpdatedAt(new \DateTime());
        $login->setStatus(LoginStatus::Active);

        $ok = $this->loginRepository->refresh(
            $login->getId(),
            $context['refresh_token'],
        );

        if (!$ok) {
            throw new \RuntimeException('failed to persist refreshed login');
        }

        $this->logger->info('login ' . $login->getId() . ' refreshed');
        return $login;
    }

    private function doExpire(Login $login): Login
    {
        if ($login->getStatus() === LoginStatus::Expired) {
            return $login;
        }

        $login->setStatus(LoginStatus::Expired);
        $login->setUpdatedAt(new \DateTime());

        $ok = $this->loginRepository->setExpired($login->getId());

        if (!$ok) {
            throw new \RuntimeException('failed to persist expired login');
        }

        $this->logger->info('login ' . $login->getId() . ' expired');
        return $login;
    }

    private function doCheckExpiry(Login $login, Realm $realm): Login
    {
        if ($login->getStatus() === LoginStatus::Expired) {
            return $login;
        }

        if ($this->isExpired($login, $realm)) {
            $login->setStatus(LoginStatus::Expired);
            $login->setUpdatedAt(new \DateTime());
        }

        return $login;
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
            throw new ValidationFailed(
                'invalid login status: expected ' . $expected->value
                . ', got ' . $login->getStatus()->value
            );
        }
    }
}
