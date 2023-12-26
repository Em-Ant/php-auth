<?php

declare(strict_types=1);

namespace AuthServer\Core\Ports\In\LoginRequest;

final class LoginRequestInput
{
    public function __construct(
        private string $realm,
        private ?string $session_id,
        private string $client_id,
        private string $state,
        private string $scope,
        private string $nonce,
        private string $redirect_uri,
        private ResponseMode $response_mode,
        private ?Prompt $propmt,
        private ?CodeChallengeMethod $code_challenge_method,
        private ?string $code_challenge,
    ) {
    }

    public function getRealm(): string
    {
        return $this->realm;
    }

    public function getSessionId(): ?string
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

    public function getScope(): string
    {
        return $this->scope;
    }

    public function getNonce(): string
    {
        return $this->nonce;
    }

    public function getRedirectUri(): string
    {
        return $this->nonce;
    }

    public function getResponseMode(): ResponseMode
    {
        return $this->response_mode;
    }

    public function getPropmpt(): ?Prompt
    {
        return $this->propmt;
    }

    public function getCodeChallengeMethod(): ?CodeChallengeMethod
    {
        return $this->code_challenge_method;
    }

    public function getCodeChallenge(): ?string
    {
        return $this->code_challenge;
    }
};
