<?php

declare(strict_types=1);

namespace AuthServer\Models;

class Client implements \JsonSerializable
{
    private string $id;
    private string $name;
    private string $realm_id;
    private ?string $client_secret;
    private string $uri;
    private bool $require_auth;
    private ?string $scope;
    private \DateTime $created_at;


    public function __construct(
        string $id,
        string $name,
        string $realm_id,
        ?string $client_secret,
        string $uri,
        bool $require_auth,
        string $created_at,
        ?string $scope = null
    ) {
        $this->id = $id;
        $this->name = $name;
        $this->realm_id = $realm_id;
        $this->uri = $uri;
        $this->client_secret = $client_secret;
        $this->require_auth = $require_auth;
        $this->scope = $scope;
        $utc = new \DateTimeZone('UTC');
        $this->created_at =
            \DateTime::createFromFormat('Y-m-d H:i:s', $created_at, $utc);
    }

    public function getId(): string
    {
        return $this->id;
    }
    public function getName(): string
    {
        return $this->name;
    }
    public function getRealmId(): string
    {
        return $this->realm_id;
    }
    public function getUri(): string
    {
        return $this->uri;
    }
    public function getClientSecret(): ?string
    {
        return $this->client_secret;
    }
    public function requiresAuth(): bool
    {
        return $this->require_auth;
    }
    public function getScope(): ?array
    {
        return $this->scope === null ? null : explode(' ', $this->scope);
    }
    public function getScopeString(): ?string
    {
        return $this->scope;
    }
    public function getCreatedAt(): \DateTime
    {
        return $this->created_at;
    }

    public function jsonSerialize(): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'realm_id' => $this->realm_id,
            'uri' => $this->uri,
            'require_auth' => $this->require_auth,
            'scope' => $this->scope,
            'created_at' => $this->created_at->format('Y-m-d H:i:s'),
        ];
    }
}
