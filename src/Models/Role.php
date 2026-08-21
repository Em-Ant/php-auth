<?php

declare(strict_types=1);

namespace AuthServer\Models;

class Role implements \JsonSerializable
{
    public function __construct(
        private readonly string $id,
        private readonly string $realmId,
        private readonly ?string $clientId,
        private readonly string $name,
        private readonly ?string $description,
        private readonly \DateTime $createdAt,
    ) {
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getRealmId(): string
    {
        return $this->realmId;
    }

    public function getClientId(): ?string
    {
        return $this->clientId;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getDescription(): ?string
    {
        return $this->description;
    }

    public function getCreatedAt(): \DateTime
    {
        return $this->createdAt;
    }

    public function isRealmRole(): bool
    {
        return $this->clientId === null;
    }

    public function isClientRole(): bool
    {
        return $this->clientId !== null;
    }

    public function jsonSerialize(): array
    {
        return [
            'id' => $this->id,
            'realm_id' => $this->realmId,
            'client_id' => $this->clientId,
            'name' => $this->name,
            'description' => $this->description,
            'created_at' => $this->createdAt->format('Y-m-d H:i:s'),
        ];
    }
}
