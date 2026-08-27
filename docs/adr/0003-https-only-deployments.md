# ADR-0003 — HTTPS-only deployments

- **Status:** Accepted
- **Date:** 2026-08-27
- **Decides:** php-auth is supported only behind TLS; plain-HTTP is not a
  supported deployment
- **Related:** F-38 (salted check-session cookie / client-side SHA-256),
  `src/Services/HttpSessionCookieHandler.php`, `src/views/login-iframe.html`

## Context

F-38 changed the 3rd-party-cookie session monitoring flow as follows:

- The `AUTH_SESSION` (HttpOnly) and `AUTH_SESSION_CHECK` (JS-readable) SSO
  cookies are now emitted with `Secure; SameSite=None` (see
  `HttpSessionCookieHandler::buildSetCookie`). A `Secure` cookie is never
  stored by a browser over plain HTTP, so the SSO session cannot be established
  on an insecure origin.
- The login-status iframe (`login-status-iframe.html`) no longer parses the raw
  session id from the cookie. It recomputes `SHA-256(session_state)` in the
  browser via the Web Crypto API (`crypto.subtle.digest`) and compares the
  base64url digest against the check cookie. `crypto.subtle` is part of the
  [secure context requirements](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts)
  and is therefore unavailable on plain HTTP (with the standard `localhost`
  exception). On HTTP the digest promise rejects, the comparison never runs,
  `postMessage` is never sent, and session monitoring silently stops working.

The pre-F-38 implementation used a plain string compare of the cookie, which
worked on any origin. That path is intentionally replaced by the salted design,
so the old behaviour is not available as a fallback.

## Decision

php-auth is supported on **HTTPS-only** deployments. TLS is a hard deployment
requirement, not an option.

Accepted consequences:

- HTTP-to-HTTPS upgrade is the operator's responsibility (reverse proxy /
  load balancer / TLS-terminating gateway). Serving `https://` directly is
  also fine.
- A reverse-proxy deployment is fully supported: configure `issuer` and
  `base_path` in `config.ini` to match the public `https://` URL. The proxy
  is expected to terminate TLS and forward as `https`.
- Local development on `http://localhost:8000` remains supported via the
  standard `localhost` secure-context exception and the non-user-facing dev
  server; this does not generalise to HTTP.

## Consequences

- Operators must not expose php-auth over plain HTTP in user-facing contexts;
  doing so yields a session-monitoring failure that is silent (no error
  surfaced to the RP), making it hard to diagnose. This risk is accepted and
  mitigated by documentation rather than by a runtime guard.
- A future "insecure iframe mode" is explicitly **not** introduced: the raw
  session id is intentionally never exposed to JS. If a non-HTTPS deployment
  must be supported, the session-monitoring feature should be disabled
  server-side (do not serve `login-status-iframe.html`), not downgraded to
  id disclosure.
