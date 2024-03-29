<?php

namespace AuthServer\Models;

class Realm implements \JsonSerializable
{
    private string $id;
    private string $name;
    private string $keys_id;
    private int $refresh_token_expires_in;
    private int $access_token_expires_in;
    private int $pending_login_expires_in;
    private int $authenticated_login_expires_in;
    private int $session_expires_in;
    private int $idle_session_expires_in;
    private array $scope;
    private \DateTime $created_at;


    public function __construct(
        string $id,
        string $name,
        string $keys_id,
        int $refresh_token_expires_in,
        int $access_token_expires_in,
        int $pending_login_expires_in,
        int $authenticated_login_expires_in,
        int $session_expires_in,
        int $idle_session_expires_in,
        string $scope,
        string $created_at
    ) {
        $this->id = $id;
        $this->name = $name;
        $this->keys_id = $keys_id;
        $this->refresh_token_expires_in = $refresh_token_expires_in;
        $this->access_token_expires_in = $access_token_expires_in;
        $this->pending_login_expires_in = $pending_login_expires_in;
        $this->authenticated_login_expires_in = $authenticated_login_expires_in;
        $this->session_expires_in = $session_expires_in;
        $this->idle_session_expires_in = $idle_session_expires_in;
        $this->scope = explode(' ', $scope);
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
    public function getKeysId()
    {
        return $this->keys_id;
    }
    public function getRefreshTokenExpiresIn(): int
    {
        return $this->refresh_token_expires_in;
    }
    public function getAccessTokenExpiresIn(): int
    {
        return $this->access_token_expires_in;
    }
    public function getPendingLoginExpiresIn(): int
    {
        return $this->pending_login_expires_in;
    }
    public function getAuthenticatedLoginExpiresIn(): int
    {
        return $this->authenticated_login_expires_in;
    }
    public function getSessionExpiresIn(): int
    {
        return $this->session_expires_in;
    }
    public function getIdleSessionExpiresIn(): int
    {
        return $this->idle_session_expires_in;
    }
    public function getScope(): array
    {
        return $this->scope;
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
