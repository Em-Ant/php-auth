<?php

namespace AuthServer\Models;

use DateTime;

class User implements \JsonSerializable
{
    private string $id;
    private string $realm_id;
    private string $name;
    private string $email;
    private string $password;
    private array $realm_roles;
    private DateTime $created_at;
    private bool $valid;

    public function __construct(
        string $id,
        string $realm_id,
        string $name,
        string $email,
        string $password,
        string $realm_roles,
        string $created_at,
        ?bool $valid = true
    ) {
        $this->id = $id;
        $this->realm_id = $realm_id;
        $this->name = $name;
        $this->email = $email;
        $this->password = $password;
        $this->realm_roles = explode(' ', $realm_roles);
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
    public function getRealmRoles(): array
    {
        return $this->realm_roles;
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
        $data = get_object_vars($this);
        $data['created_at'] = $data['created_at']->format('Y-m-d H:i:s');

        return $data;
    }
}
