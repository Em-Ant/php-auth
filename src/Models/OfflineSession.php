<?php

declare(strict_types=1);

namespace AuthServer\Models;

use DateTime;

use function AuthServer\formatSqlDatetime;
use function AuthServer\parseSqlDatetime;
use function AuthServer\sqlNow;

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
        $this->created_at = parseSqlDatetime($created_at) ?? date_create();
        $this->authenticated_at = parseSqlDatetime($authenticated_at);
        $this->updated_at = parseSqlDatetime($updated_at);
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
        return [
            'id' => $this->id,
            'realm_id' => $this->realm_id,
            'user_id' => $this->user_id,
            'client_id' => $this->client_id,
            'acr' => $this->acr,
            'scope' => $this->scope,
            'status' => $this->status->value,
            'created_at' => formatSqlDatetime($this->created_at),
            'authenticated_at' => formatSqlDatetime($this->authenticated_at),
            'updated_at' => formatSqlDatetime($this->updated_at),
        ];
    }
}
