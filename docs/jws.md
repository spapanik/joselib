# JSON Web Signatures (JWS)

A `JWS` instance binds a key to a signing algorithm. Signing and
verification never negotiate: a token is only accepted if its `alg`
header is in the allowlist chosen at construction time.

```python
from joselib import JWS, OctKey

key = OctKey.generate(32)
jws = JWS(key, "HS256")

token = jws.sign(b"payload")
payload = jws.verify(token)  # b"payload"
```

Verification failures raise `InvalidSignatureError`; a token using an
algorithm outside the allowlist raises `UnsupportedAlgorithmError`
before any cryptographic work is done.

## Supported algorithms

| Family  | Algorithms             | Key type |
| ------- | ---------------------- | -------- |
| HMAC    | HS256, HS384, HS512    | `OctKey` |
| RSA     | RS256, RS384, RS512    | `RSAKey` |
| RSA-PSS | PS256, PS384, PS512    | `RSAKey` |
| ECDSA   | ES256, ES384, ES512    | `ECKey`  |
| EdDSA   | EdDSA (Ed25519, Ed448) | `OKPKey` |

The `none` algorithm does not exist in joselib, and cannot be smuggled
in: every verification checks the allowlist first. Each algorithm also
pins its key requirements — ES256 only accepts P-256 keys, HS256 keys
must be at least 32 bytes, and so on.

## Verifying tokens from someone else

Use the public part of their key:

```python
from joselib import ECKey, JWS

verifier = JWS(ECKey.from_pem(public_pem), "ES256")
payload = verifier.verify(token)
```

To accept more than one algorithm during a migration, pass an explicit
allowlist:

```python
jws = JWS(key, "ES256", allowed_algorithms={"ES256", "ES384"})
```

## Headers

Extra protected headers can be set once at construction, or per token:

```python
jws = JWS(key, "HS256", headers={"cty": "text/plain"})
token = jws.sign(b"payload", headers={"cty": "application/json"})
```

The `alg` and `crit` headers are managed by the library and cannot be
overridden. Tokens that carry a `crit` header are rejected, as required
by RFC 7515 for implementations that support no critical extensions.

For key selection in multi-key setups, the unauthenticated header can be
inspected before choosing a verifier:

```python
header = JWS.unverified_header(token)  # never trust these values
key = my_keystore[header["kid"]]
```
