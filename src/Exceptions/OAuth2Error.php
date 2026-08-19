<?php

declare(strict_types=1);

namespace AuthServer\Exceptions;

/**
 * An RFC 6749 §5.2 OAuth 2.0 error carrying the machine-readable error code
 * and HTTP status. Extends ValidationFailed so existing callers keep working;
 * controllers catch it before the generic ValidationFailed handler to emit the
 * correct code and status.
 */
class OAuth2Error extends ValidationFailed
{
    private string $error;
    private int $status;

    public function __construct(string $error, string $description, int $status = 400)
    {
        parent::__construct($description);
        $this->error = $error;
        $this->status = $status;
    }

    public function getError(): string
    {
        return $this->error;
    }

    public function getStatus(): int
    {
        return $this->status;
    }

    public static function invalidClient(string $description): self
    {
        return new self('invalid_client', $description, 401);
    }

    public static function invalidGrant(string $description): self
    {
        return new self('invalid_grant', $description, 400);
    }

    public static function invalidScope(string $description): self
    {
        return new self('invalid_scope', $description, 400);
    }

    public static function unsupportedGrantType(string $description): self
    {
        return new self('unsupported_grant_type', $description, 400);
    }

    public static function unsupportedResponseType(string $description): self
    {
        return new self('unsupported_response_type', $description, 400);
    }
}
