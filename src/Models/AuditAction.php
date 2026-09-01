<?php

declare(strict_types=1);

namespace AuthServer\Models;

enum AuditAction: string
{
    case RealmCreate = 'realm.create';
    case RealmUpdate = 'realm.update';
    case RealmDelete = 'realm.delete';

    case ClientCreate = 'client.create';
    case ClientUpdate = 'client.update';
    case ClientDelete = 'client.delete';

    case UserCreate = 'user.create';
    case UserUpdate = 'user.update';
    case UserDelete = 'user.delete';

    case RoleCreate = 'role.create';
    case RoleUpdate = 'role.update';
    case RoleDelete = 'role.delete';

    case ScopeRoleCreate = 'scope_role.create';
    case ScopeRoleUpdate = 'scope_role.update';
    case ScopeRoleDelete = 'scope_role.delete';
}
