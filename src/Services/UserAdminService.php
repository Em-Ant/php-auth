<?php

declare(strict_types=1);

namespace AuthServer\Services;

use AuthServer\Exceptions\ConflictException;
use AuthServer\Exceptions\ValidationFailed;
use AuthServer\Interfaces\OfflineSessionRepository;
use AuthServer\Interfaces\RealmRepository;
use AuthServer\Interfaces\SessionRepository;
use AuthServer\Interfaces\UserRepository;
use AuthServer\Models\AuditAction;
use AuthServer\Models\User;
use Psr\Http\Message\ServerRequestInterface;

use function AuthServer\formatSqlDatetime;
use function AuthServer\getGuid;
use function AuthServer\sqlNow;

/**
 * Owns the atomic admin write path for users: the user row and — for password
 * rotations — the session revocation are persisted in a single transaction, so
 * a failure in any half leaves no partial state behind. Also owns the pre-write
 * guards (realm existence, duplicate email) and the guarded delete cascade.
 *
 * Role assignments are no longer handled here — consumers must create roles
 * explicitly and assign them via POST /admin/users/{id}/roles.
 */
class UserAdminService
{
    use RunsTransactions;

    public function __construct(
        private readonly \PDO $db,
        private readonly UserRepository $users,
        private readonly SessionRevocationService $revocations,
        private readonly SecretsService $secretsService,
        private readonly RealmRepository $realms,
        private readonly SessionRepository $sessions,
        private readonly OfflineSessionRepository $offlineSessions,
        private readonly AuditLogWriter $auditLog,
    ) {
    }

    /**
     * @param array{
     *     realm_id: string,
     *     email: string,
     *     password: mixed,
     *     name?: string|null,
     *     valid?: bool,
     *     email_verified?: bool,
     * } $params
     */
    public function createUser(array $params, ServerRequestInterface $request): User
    {
        $realmId = $params['realm_id'];
        if ($this->realms->findById($realmId) === null) {
            throw new ValidationFailed("unknown realm '$realmId'");
        }

        $email = $params['email'];
        if ($this->users->findByEmailAndRealmId($email, $realmId) !== null) {
            throw new ConflictException("user '$email' already exists in this realm");
        }

        $user = new User(
            getGuid(),
            $realmId,
            $params['name'] ?? '',
            $email,
            $this->hashPassword($params['password']),
            sqlNow(),
            $params['valid'] ?? true,
            $params['email_verified'] ?? true
        );

        $created = $this->transact(function () use ($user): User {
            return $this->users->create($user);
        });

        $this->auditLog->log($request, AuditAction::UserCreate, 'user', $created->getId(), $realmId);

        return $created;
    }

    /**
     * @param array{
     *     realm_id?: string|null,
     *     email?: string|null,
     *     password?: mixed,
     *     name?: string|null,
     *     valid?: bool,
     *     email_verified?: bool,
     * } $params
     *
     * `realm_id`, when provided, must equal the user's current realm:
     * moving a user across realms is rejected because role assignments are
     * realm-bound and would silently dangle against the old realm's roles.
     */
    public function updateUser(User $existing, array $params, ServerRequestInterface $request): User
    {
        $realmId = $params['realm_id'] ?? $existing->getRealmId();
        if ($this->realms->findById($realmId) === null) {
            throw new ValidationFailed("unknown realm '$realmId'");
        }
        if ($realmId !== $existing->getRealmId()) {
            throw new ValidationFailed(
                "cannot move user to another realm: roles are realm-bound and "
                . 'the user\'s assignments would not follow'
            );
        }

        $email = $params['email'] ?? $existing->getEmail();
        $duplicate = $this->users->findByEmailAndRealmId($email, $realmId);
        if ($duplicate !== null && $duplicate->getId() !== $existing->getId()) {
            throw new ConflictException("user '$email' already exists in this realm");
        }

        // A submitted password counts as a rotation: the rotation transaction
        // also drops the user's live SSO sessions and expires their offline
        // refresh grants so credentials stolen under the old password die with
        // it. Everything applies or nothing does — a failed rotation is safe
        // to retry.
        $rotating = ($params['password'] ?? null) !== null;

        $user = new User(
            $existing->getId(),
            $realmId,
            $params['name'] ?? $existing->getName(),
            $email,
            $rotating ? $this->hashPassword($params['password'] ?? null) : $existing->getPassword(),
            formatSqlDatetime($existing->getCreatedAt()),
            $params['valid'] ?? $existing->getValid(),
            $params['email_verified'] ?? $existing->getEmailVerified()
        );

        $this->transact(function () use ($user, $rotating): void {
            $this->users->update($user);
            if ($rotating) {
                $this->revocations->revokeFor($user->getId(), null);
            }
        });

        $this->auditLog->log($request, AuditAction::UserUpdate, 'user', $user->getId(), $realmId);

        return $user;
    }

    public function deleteUser(string $userId, ServerRequestInterface $request): void
    {
        $existing = $this->users->findById($userId);
        $realmId = $existing?->getRealmId();

        $this->transact(function () use ($userId): void {
            if ($this->sessions->countActiveByUserId($userId) > 0) {
                throw new ConflictException("user '$userId' still has active sessions");
            }

            if ($this->offlineSessions->countActiveByUserId($userId) > 0) {
                throw new ConflictException("user '$userId' still has active offline sessions");
            }

            // Remove the (already expired) offline grants so the FK does not
            // block the delete and no orphan rows survive the user.
            $this->offlineSessions->deleteByUserId($userId);
            $this->users->delete($userId);
        });

        if ($existing !== null) {
            $this->auditLog->log($request, AuditAction::UserDelete, 'user', $userId, $realmId);
        }
    }

    /**
     * A password was submitted when the value is non-null. One rule drives
     * both the hash decision and the rotation trigger, so a null value can
     * never count as a rotation by accident.
     */
    private function hashPassword(mixed $password): string
    {
        if (!is_string($password) || trim($password) === '') {
            throw new ValidationFailed("'password' must be a non-empty string");
        }
        return $this->secretsService->hashPassword($password);
    }
}
