<?php

declare(strict_types=1);

namespace AuthServer\Models;

use DateTime;
use DateTimeZone;

class OfflineSession implements \JsonSerializable
{
    private string $id;
    private string $realm_id;
    private string $user_id;
    private string $client_id;
    private string $acr;
    private string $scope;
    private ?string $nonce;
    private ?string $refresh_token;
    private ?DateTime $authenticated_at;
    private DateTime $created_at;
    private ?DateTime $updated_at;
    private OfflineSessionStatus $status;

    public function __construct(
        string $id,
        string $realm_id,
        string $user_id,
        string $client_id,
        string $scope,
        ?string $created_at = null,
        ?string $acr = '0',
        ?string $nonce = null,
        ?string $authenticated_at = null,
        ?string $updated_at = null,
        ?string $refresh_token = null,
        ?string $status = 'ACTIVE'
    ) {
        $this->id = $id;
        $this->realm_id = $realm_id;
        $this->user_id = $user_id;
        $this->client_id = $client_id;
        $this->scope = $scope;
        $this->acr = $acr ?? '0';
        $this->nonce = $nonce;
        $this->refresh_token = $refresh_token;
        $utc = new DateTimeZone('UTC');
        $this->created_at = is_null($created_at) ?
            date_create() :
            \DateTime::createFromFormat('Y-m-d H:i:s', $created_at, $utc);
        $this->authenticated_at = $authenticated_at === null
            ? null
            : (\DateTime::createFromFormat('Y-m-d H:i:s', $authenticated_at, $utc) ?: null);
        $this->updated_at = $updated_at === null
            ? null
            : (\DateTime::createFromFormat('Y-m-d H:i:s', $updated_at, $utc) ?: null);
        $this->status = OfflineSessionStatus::from($status ?? 'ACTIVE');
    }

    public function getId(): string
    {
        return $this->id;
    }
    public function getRealmId(): string
    {
        return $this->realm_id;
    }
    public function getUserId(): string
    {
        return $this->user_id;
    }
    public function getClientId(): string
    {
        return $this->client_id;
    }
    public function getAcr(): string
    {
        return $this->acr;
    }
    public function getScope(): string
    {
        return $this->scope;
    }
    public function getNonce(): ?string
    {
        return $this->nonce;
    }
    public function getRefreshToken(): ?string
    {
        return $this->refresh_token;
    }
    public function getAuthenticatedAt(): ?DateTime
    {
        return $this->authenticated_at;
    }
    public function getCreatedAt(): DateTime
    {
        return $this->created_at;
    }
    public function getUpdatedAt(): ?DateTime
    {
        return $this->updated_at;
    }
    public function getStatus(): OfflineSessionStatus
    {
        return $this->status;
    }

    public function setRefreshToken(?string $refreshToken): void
    {
        $this->refresh_token = $refreshToken;
    }

    public function setUpdatedAt(DateTime $updatedAt): void
    {
        $this->updated_at = $updatedAt;
    }

    public function setStatus(OfflineSessionStatus $status): void
    {
        $this->status = $status;
    }

    public function jsonSerialize(): array
    {
        $data = get_object_vars($this);
        $data['status'] = $this->status->value;
        $data['created_at'] = $data['created_at']->format('Y-m-d H:i:s');
        $data['authenticated_at'] = isset($data['authenticated_at']) ?
            $data['authenticated_at']->format('Y-m-d H:i:s') :
            null;
        $data['updated_at'] = isset($data['updated_at']) ?
            $data['updated_at']->format('Y-m-d H:i:s') :
            null;

        return $data;
    }
}
