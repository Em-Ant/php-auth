<?php

namespace AuthServer\Models;

use DateTime;

class Session implements \JsonSerializable
{
    private string $id;
    private string $realm_id;
    private string $acr;
    private string $user_id;
    private DateTime $created_at;
    private ?DateTime $updated_at;
    private string $status;

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
        $utc = new \DateTimeZone('UTC');
        $this->created_at = is_null($created_at) ?
            date_create() :
            \DateTime::createFromFormat('Y-m-d H:i:s', $created_at, $utc);
        $this->updated_at =
            \DateTime::createFromFormat('Y-m-d H:i:s', $updated_at, $utc) ?: null;
        $this->status = is_null($status) ? 'ACTIVE' : $status;
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
    public function getStatus(): string
    {
        return $this->status;
    }

    public function jsonSerialize(): array
    {
        $data = get_object_vars($this);
        $data['created_at'] = $data['created_at']->format('Y-m-d H:i:s');
        $data['updated_at'] = isset($data['updated_at']) ?
            $data['updated_at']->format('Y-m-d H:i:s') :
            null;

        return $data;
    }
}
