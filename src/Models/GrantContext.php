<?php

declare(strict_types=1);

namespace AuthServer\Models;

/**
 * Identity and authentication context a token bundle is issued from —
 * shared by every token in the bundle.
 */
final class GrantContext
{
    public function __construct(
        public readonly string $subject,
        public readonly int $authTime,
        public readonly string $acr,
        public readonly string $sid,
        public readonly ?string $nonce,
        public readonly string $scope,
    ) {
    }

    public static function fromSession(Session $session, Login $login): self
    {
        $authenticatedAt = $login->getAuthenticatedAt();

        return new self(
            subject: $session->getUserId(),
            authTime: $authenticatedAt !== null ? date_timestamp_get($authenticatedAt) : time(),
            acr: $session->getAcr(),
            sid: $session->getId(),
            nonce: $login->getNonce(),
            scope: $login->getScope(),
        );
    }

    public static function fromOfflineSession(OfflineSession $offlineSession): self
    {
        $authenticatedAt = $offlineSession->getAuthenticatedAt();

        return new self(
            subject: $offlineSession->getUserId(),
            authTime: $authenticatedAt !== null ? date_timestamp_get($authenticatedAt) : time(),
            acr: $offlineSession->getAcr(),
            sid: $offlineSession->getId(),
            nonce: $offlineSession->getNonce(),
            scope: $offlineSession->getScope(),
        );
    }

    /**
     * Same grant, narrowed scope — issuance-time role gating may drop scopes
     * from the stored grant without touching the stored login/session row.
     */
    public function withScope(string $scope): self
    {
        return new self(
            subject: $this->subject,
            authTime: $this->authTime,
            acr: $this->acr,
            sid: $this->sid,
            nonce: $this->nonce,
            scope: $scope,
        );
    }

    /**
     * Overrides the `sid` published in the issued tokens without touching the
     * grant's own session record. Lets offline grants advertise the live
     * online SSO session id (Keycloak parity for the check-session iframe,
     * F‑38) while the offline session keeps its own id for persistence.
     */
    public function withSid(string $sid): self
    {
        return new self(
            subject: $this->subject,
            authTime: $this->authTime,
            acr: $this->acr,
            sid: $sid,
            nonce: $this->nonce,
            scope: $this->scope,
        );
    }
}
