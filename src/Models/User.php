<?php

declare(strict_types=1);

namespace AuthServer\Models;

use DateTime;

class User implements \JsonSerializable
{
    private string $id;
    private string $realm_id;
    private string $name;
    private string $email;
    private string $password;
    /** @var list<string> */
    private array $realmRoles;
    /** @var array<string, list<string>> */
    private array $clientRoles;
    private DateTime $created_at;
    private bool $valid;

    /**
     * @param list<string> $realmRoles
     * @param array<string, list<string>> $clientRoles
     */
    public function __construct(
        string $id,
        string $realm_id,
        string $name,
        string $email,
        string $password,
        array $realmRoles,
        string $created_at,
        ?bool $valid = true,
        array $clientRoles = []
    ) {
        $this->id = $id;
        $this->realm_id = $realm_id;
        $this->name = $name;
        $this->email = $email;
        $this->password = $password;
        $this->realmRoles = $realmRoles;
        $this->clientRoles = $clientRoles;
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
    /** @return list<string> */
    public function getRealmRoles(): array
    {
        return $this->realmRoles;
    }

    /** @return array<string, list<string>> */
    public function getClientRoles(): array
    {
        return $this->clientRoles;
    }

    /** @return list<string> */
    public function getClientRoleNames(string $clientName): array
    {
        return $this->clientRoles[$clientName] ?? [];
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
            'realm_roles' => $this->realmRoles,
            'client_roles' => $this->clientRoles,
            'valid' => $this->valid,
            'created_at' => $this->created_at->format('Y-m-d H:i:s'),
        ];
    }
}
