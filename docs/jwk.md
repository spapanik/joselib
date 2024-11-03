# JSON Web Keys (JWK)

All joselib operations work on `Key` objects. There is one class per JWK
key type, and all of them are immutable once created:

| Class    | `kty` | Used for                                     |
| -------- | ----- | -------------------------------------------- |
| `OctKey` | oct   | HMAC signatures, JWE key wrapping/encryption |
| `RSAKey` | RSA   | RS*/PS* signatures, RSA-OAEP key wrapping    |
| `ECKey`  | EC    | ES* signatures (P-256, P-384, P-521)         |
| `OKPKey` | OKP   | EdDSA signatures (Ed25519, Ed448)            |

## Generating keys

```python
from joselib import ECKey, OctKey, OKPKey, RSAKey

symmetric = OctKey.generate(32)  # size in bytes
rsa = RSAKey.generate()  # 2048 bits by default, the allowed minimum
ec = ECKey.generate("P-256")
ed = OKPKey.generate("Ed25519")
```

## Importing and exporting keys

Keys can be imported from a JWK (as a dict or a JSON string) or from a
PEM-encoded file:

```python
from joselib import ECKey, Key

key = Key.from_jwk({"kty": "EC", "crv": "P-256", "x": "...", "y": "..."})
key = ECKey.from_jwk('{"kty": "EC", ...}')  # also enforces the key type
key = ECKey.from_pem(pem_bytes, password=None)
```

`Key.from_jwk` dispatches on `kty`; using a concrete class such as
`ECKey.from_jwk` additionally fails with `JWKError` if the JWK is of a
different type.

Exporting is explicit about private material: `to_jwk()` and `to_pem()`
only ever emit the public part, and exporting a private key requires
`private=True`. Symmetric keys refuse to export without `private=True`,
as they have no public part.

```python
public_jwk = key.to_jwk()
private_jwk = key.to_jwk(private=True)
public_pem = key.to_pem()
```

## Other operations

```python
key.is_private  # True if the private part is present
key.public()  # the same key without the private part
key.thumbprint()  # RFC 7638 SHA-256 thumbprint (base64url string)
key.kid  # optional key ID, set at creation or imported from the JWK
```

A `kid` set on a key is automatically included in the protected header of
every JWS or JWE created with it.

## Security notes

- RSA keys below 2048 bits and oct keys below 16 bytes are rejected.
- Only the NIST curves P-256, P-384, and P-521 (and Ed25519/Ed448 for
  OKP) are supported.
- An OKP private JWK whose `x` does not match its `d` is rejected.
- All parsing is strict: unpadded canonical base64url and duplicate-free
  JSON are required.
