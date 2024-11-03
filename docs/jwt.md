# JSON Web Tokens (JWT)

`JWT` builds on [JWS](jws.md), adding JSON claims and their validation.
All validation policy lives on the instance, so tokens all over a
codebase are checked consistently.

```python
import time

from joselib import JWT, OctKey

key = OctKey.generate(32)
jwt = JWT(key, "HS256", issuer="https://issuer.example", audience="my-api")

token = jwt.encode(
    {
        "iss": "https://issuer.example",
        "aud": "my-api",
        "sub": "user-42",
        "exp": int(time.time()) + 300,
    }
)
claims = jwt.decode(token)
```

`encode` also accepts timezone-aware `datetime` objects for `exp`,
`nbf`, and `iat`, converting them to numeric timestamps; naive datetimes
are rejected.

## Validation

`decode` verifies the signature first and then validates the claims,
raising a subclass of `JWTError` on the first problem:

- `exp` and `nbf` are checked against the current time (accepting the
  configured `leeway`, in seconds); an expired token raises
  `ExpiredTokenError`.
- `exp`, `nbf`, and `iat` must be numbers, and `sub` and `jti` must be
  strings, whenever they are present.
- `iss` must equal the configured `issuer`, if one was configured.
- `aud` must contain the configured `audience`. A token that carries an
  audience when none is expected is rejected, as is a missing audience
  when one is expected.
- Claims listed in `required_claims` must be present:

```python
jwt = JWT(key, "HS256", required_claims={"exp", "sub"})
```

Anything else raises `InvalidClaimError`, which carries the offending
claim name in its `claim` attribute.

## Verifying third-party tokens

```python
from joselib import JWT, RSAKey

verifier = JWT(
    RSAKey.from_jwk(public_jwk),
    "RS256",
    issuer="https://issuer.example",
    audience="my-api",
    leeway=30,
)
claims = verifier.decode(token)
```

The algorithm allowlist works exactly as in [JWS](jws.md): a token whose
`alg` differs from the configured algorithms is rejected before any
cryptographic work, which rules out algorithm-confusion attacks by
construction.
