<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\StorageFailed;
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

    public function findByCode(string $code, string $realmId): ?Login
    {
        return $this->loginRepository->findByCode($code, $realmId);
    }

    public function findByRefreshToken(string $token, string $realmId): ?Login
    {
        return $this->loginRepository->findByRefreshToken($token, $realmId);
    }

    private function doAuthenticate(Login $login, Realm $realm, array $context): Login
    {
        $this->assertStatus($login, LoginStatus::Pending);

        $this->assertNotExpired($login, $realm);

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
            throw new StorageFailed('failed to persist authenticated login');
        }

        $this->logState('authenticated', $login);
        return $login;
    }

    private function doActivate(Login $login, Realm $realm, array $context): Login
    {
        $this->assertStatus($login, LoginStatus::Authenticated);

        $this->assertNotExpired($login, $realm);

        $login->setRefreshToken($context['refresh_token']);
        $login->setUpdatedAt(new \DateTime());
        $login->setStatus(LoginStatus::Active);

        $ok = $this->loginRepository->setActive(
            $login->getId(),
            $context['refresh_token'],
        );

        if (!$ok) {
            throw new StorageFailed('failed to persist activated login');
        }

        $this->logState('activated', $login);
        return $login;
    }

    private function doRefresh(Login $login, Realm $realm, array $context): Login
    {
        $this->assertStatus($login, LoginStatus::Active);

        $this->assertNotExpired($login, $realm);

        $login->setRefreshToken($context['refresh_token']);
        $login->setUpdatedAt(new \DateTime());
        $login->setStatus(LoginStatus::Active);

        $ok = $this->loginRepository->refresh(
            $login->getId(),
            $context['refresh_token'],
        );

        if (!$ok) {
            throw new StorageFailed('failed to persist refreshed login');
        }

        $this->logState('refreshed', $login);
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
            throw new StorageFailed('failed to persist expired login');
        }

        $this->logState('expired', $login);
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

    private function assertNotExpired(Login $login, Realm $realm): void
    {
        if (!$this->isExpired($login, $realm)) {
            return;
        }

        $login->setStatus(LoginStatus::Expired);
        throw new ValidationFailed($login->getStatus()->value . ' login expired');
    }

    private function logState(string $action, Login $login): void
    {
        $this->logger->info('login ' . $login->getId() . ' ' . $action);
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
