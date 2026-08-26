# 12: `findScopeRoleMapping` returns raw `?array` instead of typed model

**Status**: Open
**Severity**: Minor
**File**: `src/Repositories/RoleRepository.php:403`

## Problem

Every other finder method returns a typed model object (`?Client`, `?Login`, `?Role`, etc.). `findScopeRoleMapping` returns a raw `PDO::FETCH_BOTH` array. The interface declares `?array`, so the contract is met, but it's inconsistent with the rest of the codebase.

Note: `findScopeRoleMappings` (plural, line 176) already constructs `ScopeRoleMapping` objects. The singular method simply doesn't bother.

## Fix

Change the return type from `?array` to `?ScopeRoleMapping` in both the interface (`RoleRepository`) and the implementation. Update any callers that currently destructure the raw array.
