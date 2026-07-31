# Login Methods

## Problem Statement

The server only supports the OIDC authorization-code flow. Production
integrations also need machine-to-machine and legacy credentials flows.

## User Stories

1. As a service, I want to authenticate with a `client_id`/`client_secret`
   (`grant_type=client_credentials`), so that server-to-server integrations
   get tokens without an interactive login.
2. As a developer, I want grant types modelled as an enum, so that adding a
   new grant is a single switch instead of scattered string comparisons.
3. *(future)* As a user, I want `grant_type=password` and email magic links.

## Implementation Decisions

- RFC 6749 §4.4 Client Credentials: access token only, no refresh token, no
  id_token, no session/login row.
- `GrantType` enum in `src/Models/` (backed string enum, same pattern as
  `LoginEvent`/`LoginStatus`).
- Token payload: `typ: Bearer`, `sub`/`azp`/`aud` = client name, no `sid` or
  `session_state` (no session exists).
- Client authentication matches the existing token endpoint: secret is
  validated when the client `require_auth` flag is set.
- Fixes pre-existing bug where the token endpoint read the client secret from
  `$params['code']` instead of `$params['client_secret']` — secret validation
  never ran before.

## Out of Scope

- `grant_type=password` (next issue in this directory).
- Service-account users / user impersonation.

## Issues

- [#01](issues/01-client-credentials-grant.md) — Client Credentials grant + GrantType enum
