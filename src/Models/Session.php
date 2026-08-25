<?php

declare(strict_types=1);

namespace AuthServer\Models;

use DateTime;

use function AuthServer\formatSqlDatetime;
use function AuthServer\parseSqlDatetime;

class Session implements \JsonSerializable
{
    private string $id;
    private string $realm_id;
    private string $acr;
    private string $user_id;
    private DateTime $created_at;
    private ?DateTime $updated_at;
    private SessionStatus $status;

    public function __construct(
        string $id,
        string $realm_id,
        string $user_id,
        string $acr,
        ?string $created_at = null,
        ?string $updated_at = null,
        ?string $status = 'ACTIVE'
    ) {
        $this->id = $id;
        $this->realm_id = $realm_id;
        $this->acr = $acr;
        $this->user_id = $user_id;
        $this->created_at = parseSqlDatetime($created_at) ?? date_create();
        $this->updated_at = parseSqlDatetime($updated_at);
        $this->status = SessionStatus::from($status ?? 'ACTIVE');
    }

    public function getId(): string
    {
        return $this->id;
    }
    public function getRealmId(): string
    {
        return $this->realm_id;
    }
    public function getAcr(): string
    {
        return $this->acr;
    }
    public function getUserId(): string
    {
        return $this->user_id;
    }
    public function getCreatedAt(): \DateTime
    {
        return $this->created_at;
    }
    public function getUpdatedAt(): ?\DateTime
    {
        return $this->updated_at;
    }
    public function getStatus(): SessionStatus
    {
        return $this->status;
    }

    public function jsonSerialize(): array
    {
        return [
            'id' => $this->id,
            'realm_id' => $this->realm_id,
            'user_id' => $this->user_id,
            'acr' => $this->acr,
            'status' => $this->status->value,
            'created_at' => formatSqlDatetime($this->created_at),
            'updated_at' => formatSqlDatetime($this->updated_at),
        ];
    }
}
