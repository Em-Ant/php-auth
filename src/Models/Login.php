<?php

declare(strict_types=1);

namespace AuthServer\Models;

use DateTime;
use DateTimeZone;

class Login implements \JsonSerializable
{
    private string $id;
    private ?string $session_id;
    private string $client_id;
    private string $state;
    private string $nonce;
    private string $scope;
    private string $redirect_uri;
    private string $response_mode;
    private DateTime $created_at;
    private ?string $code;
    private ?string $code_challenge;
    private ?string $csrf_token;
    private ?DateTime $authenticated_at;
    private ?string $refresh_token;
    private ?DateTime $updated_at;
    private LoginStatus $status;

    public function __construct(
        string $id,
        string $client_id,
        string $state,
        string $nonce,
        string $scope,
        string $redirect_uri,
        string $response_mode,
        ?string $created_at,
        ?string $session_id,
        ?string $authenticated_at,
        ?string $code,
        ?string $code_challenge,
        ?string $csrf_token,
        ?string $updated_at,
        ?string $refresh_token,
        ?string $status = 'PENDING'
    ) {
        $this->id = $id;
        $this->session_id = $session_id;
        $this->client_id = $client_id;
        $this->state = $state;
        $this->nonce = $nonce;
        $this->scope = $scope;
        $this->redirect_uri = $redirect_uri;
        $this->response_mode = $response_mode;
        $this->code = $code;
        $this->code_challenge = $code_challenge;
        $this->csrf_token = $csrf_token;
        $this->refresh_token = $refresh_token;
        $utc = new DateTimeZone('UTC');
        $this->created_at = is_null($created_at) ?
            date_create() :
            \DateTime::createFromFormat('Y-m-d H:i:s', $created_at, $utc);
        $this->updated_at = is_null($updated_at)
            ? null
            : (\DateTime::createFromFormat('Y-m-d H:i:s', $updated_at, $utc) ?: null);
        $this->authenticated_at = is_null($authenticated_at)
            ? null
            : (\DateTime::createFromFormat('Y-m-d H:i:s', $authenticated_at, $utc) ?: null);
        $this->status = LoginStatus::from($status ?? 'PENDING');
    }

    public function getId(): string
    {
        return $this->id;
    }
    public function getSessionId(): string
    {
        return $this->session_id;
    }
    public function getClientId(): string
    {
        return $this->client_id;
    }
    public function getState(): string
    {
        return $this->state;
    }
    public function getNonce(): string
    {
        return $this->nonce;
    }
    public function getScope(): string
    {
        return $this->scope;
    }
    public function getRedirectUri(): string
    {
        return $this->redirect_uri;
    }
    public function getResponseMode(): string
    {
        return $this->response_mode;
    }
    public function getCode(): ?string
    {
        return $this->code;
    }
    public function getCodeChallenge(): ?string
    {
        return $this->code_challenge;
    }
    public function getCsrfToken(): ?string
    {
        return $this->csrf_token;
    }
    public function getRefreshToken(): ?string
    {
        return $this->refresh_token;
    }
    public function getCreatedAt(): \DateTime
    {
        return $this->created_at;
    }
    public function getAuthenticatedAt(): ?\DateTime
    {
        return $this->authenticated_at;
    }
    public function getUpdatedAt(): ?\DateTime
    {
        return $this->updated_at;
    }
    public function getStatus(): LoginStatus
    {
        return $this->status;
    }

    public function jsonSerialize(): array
    {
        $data = get_object_vars($this);
        $data['status'] = $this->status->value;
        $data['created_at'] = $data['created_at']->format('Y-m-d H:i:s');
        $data['authenticated_at'] = isset($data['authenticated_at']) ?
            $data['authenticated_at']->format('Y-m-d H:i:s') :
            null;
        $data['updated_at'] = isset($data['updated_at']) ?
            $data['updated_at']->format('Y-m-d H:i:s') :
            null;

        return $data;
    }
}
