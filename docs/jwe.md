# JSON Web Encryption (JWE)

A `JWE` instance binds a key to a key-management algorithm (`alg`) and a
content-encryption algorithm (`enc`). Decryption is strict: a token is
only accepted if both its `alg` and `enc` headers match the instance
exactly.

```python
from joselib import JWE, OctKey

key = OctKey.generate(32)
jwe = JWE(key, "dir", "A256GCM")

token = jwe.encrypt(b"attack at dawn")
plaintext = jwe.decrypt(token)  # b"attack at dawn"
```

Any decryption failure — wrong key, tampered ciphertext, malformed
padding — raises the same `DecryptionError`, without leaking which step
failed.

## Supported algorithms

Key management (`alg`):

| Algorithm                  | Key type            |
| -------------------------- | ------------------- |
| dir                        | `OctKey` (CEK size) |
| A128KW, A192KW, A256KW     | `OctKey` (16/24/32) |
| RSA-OAEP, RSA-OAEP-256     | `RSAKey`            |

Content encryption (`enc`):

| Algorithm                                    | CEK size     |
| -------------------------------------------- | ------------ |
| A128GCM, A192GCM, A256GCM                    | 16/24/32     |
| A128CBC-HS256, A192CBC-HS384, A256CBC-HS512  | 32/48/64     |

`RSA1_5` is deliberately not implemented (padding-oracle attacks), and
neither is the `zip` header: compressing plaintext before encryption
leaks information about it and enables decompression bombs. Tokens using
either are rejected.

## Encrypting for someone else

Use the public part of their RSA key:

```python
from joselib import JWE, RSAKey

jwe = JWE(RSAKey.from_pem(public_pem), "RSA-OAEP-256", "A256GCM")
token = jwe.encrypt(b"for their eyes only")
```

## Headers

Extra protected headers can be added per token; `alg`, `enc`, `zip`, and
`crit` are managed by the library and cannot be set:

```python
token = jwe.encrypt(b"data", headers={"cty": "text/plain"})
```
