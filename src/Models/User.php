<?php

declare(strict_types=1);

namespace AuthServer\Models;

use DateTime;

/**
 * A pure row model for `users`. Role assignments are not carried here —
 * they live in the roles tables and are read through RoleRepository by the
 * services that need them (token claims, future admin role mapping).
 */
class User implements \JsonSerializable
{
    private string $id;
    private string $realm_id;
    private string $name;
    private string $email;
    private string $password;
    private DateTime $created_at;
    private bool $valid;

    public function __construct(
        string $id,
        string $realm_id,
        string $name,
        string $email,
        string $password,
        string $created_at,
        ?bool $valid = true
    ) {
        $this->id = $id;
        $this->realm_id = $realm_id;
        $this->name = $name;
        $this->email = $email;
        $this->password = $password;
        $utc = new \DateTimeZone('UTC');
        $this->created_at =
            \DateTime::createFromFormat('Y-m-d H:i:s', $created_at, $utc);
        $this->valid = $valid;
    }

    public function getId(): string
    {
        return $this->id;
    }
    public function getRealmId(): string
    {
        return $this->realm_id;
    }
    public function getName(): string
    {
        return $this->name;
    }
    public function getEmail(): string
    {
        return $this->email;
    }
    public function getPassword(): string
    {
        return $this->password;
    }
    public function getCreatedAt(): \DateTime
    {
        return $this->created_at;
    }
    public function getValid(): bool
    {
        return $this->valid;
    }

    public function jsonSerialize(): array
    {
        return [
            'id' => $this->id,
            'realm_id' => $this->realm_id,
            'name' => $this->name,
            'email' => $this->email,
            'valid' => $this->valid,
            'created_at' => $this->created_at->format('Y-m-d H:i:s'),
        ];
    }
}
