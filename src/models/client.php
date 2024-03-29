<?php

namespace AuthServer\Models;

class Client implements \JsonSerializable
{
    private string $id;
    private string $name;
    private string $realm_id;
    private ?string $client_secret;
    private string $uri;
    private bool $require_auth;
    private \DateTime $created_at;


    public function __construct(
        string $id,
        string $name,
        string $realm_id,
        ?string $client_secret,
        string $uri,
        bool $require_auth,
        string $created_at
    ) {
        $this->id = $id;
        $this->name = $name;
        $this->realm_id = $realm_id;
        $this->uri = $uri;
        $this->client_secret = $client_secret;
        $this->require_auth = $require_auth;
        $utc = new \DateTimeZone('UTC');
        $this->created_at =
            \DateTime::createFromFormat('Y-m-d H:i:s', $created_at, $utc);
    }

    public function getId()
    {
        return $this->id;
    }
    public function getName()
    {
        return $this->name;
    }
    public function getRealmId()
    {
        return $this->realm_id;
    }
    public function getUri()
    {
        return $this->uri;
    }
    public function getClientSecret()
    {
        return $this->client_secret;
    }
    public function requiresAuth(): bool
    {
        return $this->require_auth;
    }
    public function getCreatedAt(): \DateTime
    {
        return $this->created_at;
    }

    public function jsonSerialize(): array
    {
        $data = get_object_vars($this);
        $data['created_at'] = $data['created_at']->format('Y-m-d H:i:s');
        return $data;
    }
}
