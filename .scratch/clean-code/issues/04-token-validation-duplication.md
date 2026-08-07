# Token validation knowledge duplicated

**Severity:** low.

Token decoding/validation is spread across `TokenGrantService`, `TokenIntrospectionService`, `TokenRevocationService`, and `AuthenticationOrchestrator` with subtly different claim checks — expiry checked as `tokenIsExpired()` in some places, `exp < time()` in others; audience/issuer never validated consistently.

**Fix:** centralize claim validation (signature, exp, aud, iss, typ, blacklist) behind one `TokenService`/`TokenValidator` method so all four flows share the same policy.
