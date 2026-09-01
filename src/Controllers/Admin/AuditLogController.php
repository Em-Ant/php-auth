<?php

declare(strict_types=1);

namespace AuthServer\Controllers\Admin;

use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\AuditLogRepository;
use AuthServer\Models\AuditLogEntry;
use AuthServer\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Exception\HttpNotFoundException;

class AuditLogController
{
    use ValidatesAdminInput;

    public function __construct(
        private readonly AuditLogRepository $auditLogs,
    ) {
    }

    public function list(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $query = $request->getQueryParams();
        ['limit' => $limit, 'offset' => $offset] = $this->paginationFromQuery($query);

        $from = $this->queryString($query, 'from');
        $to = $this->queryString($query, 'to');

        if ($this->hasInvalidDateRange($from, $to)) {
            return JsonResponse::error(
                $response,
                'invalid_request',
                "'from' and 'to' must be valid ISO dates (YYYY-MM-DD)",
                400,
            );
        }

        $result = $this->auditLogs->searchAll(
            $this->queryString($query, 'action'),
            $this->queryString($query, 'actor_type'),
            $this->queryString($query, 'target_type'),
            $this->queryString($query, 'realm_id'),
            $from,
            $this->endOfDay($to),
            $limit,
            $offset,
        );

        return JsonResponse::paginated(
            $response,
            array_map(static fn(AuditLogEntry $e): array => $e->jsonSerialize(), $result['items']),
            $result['total'],
            $limit,
            $offset,
        );
    }

    public function read(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $entry = $this->findEntryOrFail($request, $request->getAttribute('id'));

        return JsonResponse::create($response, $entry->jsonSerialize());
    }

    public function purge(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        try {
            $body = (array) ($request->getParsedBody() ?? []);
            $query = $request->getQueryParams();

            $realmId = $this->optionalString($body, 'realm_id', null)
                ?? $this->queryString($query, 'realm_id');
            $olderThan = $this->optionalString($body, 'older_than', null)
                ?? $this->queryString($query, 'older_than');

            $error = $this->purgeValidationError($realmId, $olderThan);
        } catch (ValidationFailed $e) {
            return JsonResponse::error($response, 'invalid_request', $e->getMessage(), 400);
        }

        if ($error !== null) {
            return JsonResponse::error($response, 'invalid_request', $error, 400);
        }

        $deleted = $this->auditLogs->purge($realmId, $olderThan);

        return JsonResponse::create($response, ['deleted' => $deleted]);
    }

    private function purgeValidationError(?string $realmId, ?string $olderThan): ?string
    {
        if ($realmId === null && $olderThan === null) {
            return 'at least one of realm_id or older_than is required';
        }

        if ($olderThan !== null && $this->isValidIsoDate($olderThan) === false) {
            return "'older_than' must be a valid ISO date (YYYY-MM-DD)";
        }

        return null;
    }

    private function hasInvalidDateRange(?string $from, ?string $to): bool
    {
        return ($from !== null && !$this->isValidIsoDate($from))
            || ($to !== null && !$this->isValidIsoDate($to));
    }

    /**
     * A bare date (YYYY-MM-DD) extends to the end of that day, because
     * created_at carries a time component.
     */
    private function endOfDay(?string $date): ?string
    {
        return $date === null ? null : $date . ' 23:59:59';
    }

    private function findEntryOrFail(ServerRequestInterface $request, string $id): AuditLogEntry
    {
        $entry = $this->auditLogs->findById($id);
        if ($entry === null) {
            throw new HttpNotFoundException($request, "audit log entry '$id' not found");
        }
        return $entry;
    }

    private function isValidIsoDate(string $value): bool
    {
        if (preg_match('/^(\d{4})-(\d{2})-(\d{2})$/', $value, $matches) !== 1) {
            return false;
        }

        return checkdate((int) $matches[2], (int) $matches[3], (int) $matches[1]);
    }
}
