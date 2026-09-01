<?php

declare(strict_types=1);

namespace AuthServer\Models;

class AuditLogEntry implements \JsonSerializable
{
    private string $id;
    private AuditAction $action;
    private string $actorType;
    private ?string $actorId;
    private ?string $realmId;
    private string $targetType;
    private ?string $targetId;
    private ?string $detail;
    private string $createdAt;

    public function __construct(
        string $id,
        AuditAction $action,
        string $actorType,
        ?string $actorId,
        ?string $realmId,
        string $targetType,
        ?string $targetId,
        ?string $detail,
        string $createdAt,
    ) {
        $this->id = $id;
        $this->action = $action;
        $this->actorType = $actorType;
        $this->actorId = $actorId;
        $this->realmId = $realmId;
        $this->targetType = $targetType;
        $this->targetId = $targetId;
        $this->detail = $detail;
        $this->createdAt = $createdAt;
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getAction(): AuditAction
    {
        return $this->action;
    }

    public function getActorType(): string
    {
        return $this->actorType;
    }

    public function getActorId(): ?string
    {
        return $this->actorId;
    }

    public function getRealmId(): ?string
    {
        return $this->realmId;
    }

    public function getTargetType(): string
    {
        return $this->targetType;
    }

    public function getTargetId(): ?string
    {
        return $this->targetId;
    }

    public function getDetail(): ?string
    {
        return $this->detail;
    }

    public function getCreatedAt(): string
    {
        return $this->createdAt;
    }

    public function jsonSerialize(): array
    {
        return [
            'id' => $this->id,
            'action' => $this->action->value,
            'actor_type' => $this->actorType,
            'actor_id' => $this->actorId,
            'realm_id' => $this->realmId,
            'target_type' => $this->targetType,
            'target_id' => $this->targetId,
            'detail' => $this->detail !== null ? json_decode($this->detail, true) : null,
            'created_at' => $this->createdAt,
        ];
    }
}
