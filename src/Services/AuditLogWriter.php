<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Interfaces\AuditLogRepository;
use AuthServer\Models\AuditAction;
use AuthServer\Models\AuditLogEntry;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;

use function AuthServer\getGuid;
use function AuthServer\sqlNow;

/**
 * Shared audit-log writer. Centralises actor resolution, request-body
 * redaction, encoding, and best-effort persistence so individual admin
 * services stay focused on business logic.
 *
 * Failures are logged and swallowed — audit never aborts the originating
 * operation.
 */
class AuditLogWriter
{
    /** @var list<string> Request-body fields that must never appear in plaintext in the audit log. */
    private const REDACTED_FIELDS = ['password', 'client_secret'];

    public function __construct(
        private readonly AuditLogRepository $auditLog,
        private readonly LoggerInterface $logger,
    ) {
    }

    /**
     * Best-effort audit write. Never throws.
     *
     * @param array<string, mixed> $extraDetail Fields merged into the stored
     *                                          detail on top of the request body
     *                                          (e.g. identifiers that come from
     *                                          the route, not the payload).
     */
    public function log(
        ServerRequestInterface $request,
        AuditAction $action,
        string $targetType,
        ?string $targetId,
        ?string $realmId,
        array $extraDetail = [],
    ): void {
        try {
            $this->auditLog->create(new AuditLogEntry(
                id: getGuid(),
                action: $action,
                actorType: $request->getAttribute('admin_claims') !== null ? 'admin_user' : 'api_key',
                actorId: $request->getAttribute('admin_user'),
                realmId: $realmId,
                targetType: $targetType,
                targetId: $targetId,
                detail: $this->encodeDetail($request, $extraDetail),
                createdAt: sqlNow(),
            ));
        } catch (\Throwable $e) {
            $this->logger->warning('audit log write failed: ' . $e->getMessage());
        }
    }

    /**
     * @param array<string, mixed> $extraDetail
     */
    private function encodeDetail(ServerRequestInterface $request, array $extraDetail): ?string
    {
        $body = $request->getParsedBody();
        if (is_array($body) && $body !== []) {
            $extraDetail = array_merge($extraDetail, $body);
        }

        if ($extraDetail === []) {
            return null;
        }

        $encoded = json_encode($this->redact($extraDetail), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);

        return $encoded === false ? null : $encoded;
    }

    /**
     * @param array<string, mixed> $body
     * @return array<string, mixed>
     */
    private function redact(array $body): array
    {
        foreach (self::REDACTED_FIELDS as $field) {
            if (array_key_exists($field, $body)) {
                $body[$field] = '***';
            }
        }

        return $body;
    }
}
