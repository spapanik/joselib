import pytest

from joselib.exceptions import DecryptionError, JWEError, UnsupportedAlgorithmError
from joselib.jwe import JWE
from joselib.jwk import OctKey, RSAKey
from joselib.utils import b64url_decode, b64url_encode, json_decode, json_encode

_CEK_SIZES = {
    "A128CBC-HS256": 32,
    "A192CBC-HS384": 48,
    "A256CBC-HS512": 64,
    "A128GCM": 16,
    "A192GCM": 24,
    "A256GCM": 32,
}
# The JWE example from RFC 7516, appendix A.3.
RFC_7516_JWE = (
    "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"
    ".6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"
    ".AxY8DCtDaGlsbGljb3RoZQ"
    ".KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY"
    ".U0m_YmjN04DJvceFICbCVQ"
)
RFC_7516_JWK = {"kty": "oct", "k": "GawgguFyGrWKav7AX4VKUg"}


def alter_header(token: str, updates: dict[str, object]) -> str:
    segments = token.split(".")
    header = json_decode(b64url_decode(segments[0].encode()))
    header.update(updates)
    segments[0] = b64url_encode(json_encode(header)).decode()
    return ".".join(segments)


def flip_byte(token: str, segment: int) -> str:
    segments = token.split(".")
    raw = bytearray(b64url_decode(segments[segment].encode()))
    raw[0] ^= 1
    segments[segment] = b64url_encode(bytes(raw)).decode()
    return ".".join(segments)


class TestJWE:
    @pytest.mark.parametrize("encryption", sorted(_CEK_SIZES))
    @pytest.mark.parametrize("algorithm", ["dir", "A128KW", "A192KW", "A256KW"])
    def test_symmetric_round_trip(self, algorithm: str, encryption: str) -> None:
        if algorithm == "dir":
            key = OctKey.generate(_CEK_SIZES[encryption])
        else:
            key = OctKey.generate(int(algorithm[1:4]) // 8)
        jwe = JWE(key, algorithm, encryption)
        token = jwe.encrypt(b"attack at dawn")
        assert jwe.decrypt(token) == b"attack at dawn"

    @pytest.mark.parametrize("algorithm", ["RSA-OAEP", "RSA-OAEP-256"])
    def test_rsa_round_trip(self, algorithm: str, rsa_key: RSAKey) -> None:
        jwe = JWE(rsa_key, algorithm, "A128GCM")
        token = jwe.encrypt(b"attack at dawn")
        assert jwe.decrypt(token) == b"attack at dawn"
        assert jwe.decrypt(token.encode()) == b"attack at dawn"

    @pytest.mark.parametrize("algorithm", ["RSA1_5", "none", "ECDH-ES"])
    def test_unsupported_algorithms(self, oct_key: OctKey, algorithm: str) -> None:
        with pytest.raises(UnsupportedAlgorithmError):
            JWE(oct_key, algorithm, "A128GCM")

    def test_unsupported_encryption(self, oct_key: OctKey) -> None:
        with pytest.raises(UnsupportedAlgorithmError):
            JWE(oct_key, "dir", "A128GCM-HS256")

    @pytest.mark.parametrize("field", ["alg", "enc", "zip", "crit"])
    def test_reserved_headers(self, field: str) -> None:
        jwe = JWE(OctKey.generate(16), "dir", "A128GCM")
        with pytest.raises(JWEError):
            jwe.encrypt(b"data", headers={field: "DEF"})

    def test_custom_headers(self) -> None:
        jwe = JWE(OctKey.generate(16), "dir", "A128GCM")
        token = jwe.encrypt(b"data", headers={"cty": "text/plain"})
        header = json_decode(b64url_decode(token.split(".")[0].encode()))
        assert header == {"alg": "dir", "enc": "A128GCM", "cty": "text/plain"}
        assert jwe.decrypt(token) == b"data"

    def test_kid_in_header(self) -> None:
        key = OctKey(b"\x00" * 16, kid="a-kid")
        token = JWE(key, "dir", "A128GCM").encrypt(b"data")
        header = json_decode(b64url_decode(token.split(".")[0].encode()))
        assert header["kid"] == "a-kid"

    @pytest.mark.parametrize("token", ["", "a.b.c", "a.b.c.d.e.f"])
    def test_rejects_wrong_segment_count(self, token: str) -> None:
        jwe = JWE(OctKey.generate(16), "dir", "A128GCM")
        with pytest.raises(JWEError):
            jwe.decrypt(token)

    def test_rejects_algorithm_mismatch(self) -> None:
        key = OctKey.generate(16)
        token = JWE(key, "A128KW", "A128GCM").encrypt(b"data")
        with pytest.raises(UnsupportedAlgorithmError):
            JWE(key, "dir", "A128GCM").decrypt(token)

    def test_rejects_encryption_mismatch(self) -> None:
        key = OctKey.generate(16)
        token = JWE(key, "A128KW", "A128GCM").encrypt(b"data")
        with pytest.raises(UnsupportedAlgorithmError):
            JWE(key, "A128KW", "A256GCM").decrypt(token)

    @pytest.mark.parametrize(
        "updates", [{"zip": "DEF"}, {"crit": ["exp"]}], ids=["zip", "crit"]
    )
    def test_rejects_reserved_token_headers(self, updates: dict[str, object]) -> None:
        jwe = JWE(OctKey.generate(16), "dir", "A128GCM")
        token = alter_header(jwe.encrypt(b"data"), updates)
        with pytest.raises(JWEError):
            jwe.decrypt(token)

    @pytest.mark.parametrize("segment", [2, 3, 4], ids=["iv", "ciphertext", "tag"])
    def test_rejects_tampered_tokens(self, segment: int) -> None:
        jwe = JWE(OctKey.generate(16), "dir", "A128GCM")
        token = jwe.encrypt(b"data")
        with pytest.raises(DecryptionError):
            jwe.decrypt(flip_byte(token, segment))

    def test_rejects_wrong_key(self) -> None:
        token = JWE(OctKey.generate(16), "A128KW", "A128GCM").encrypt(b"data")
        with pytest.raises(DecryptionError):
            JWE(OctKey.generate(16), "A128KW", "A128GCM").decrypt(token)

    def test_rfc_7516_a3_vector(self) -> None:
        key = OctKey.from_jwk(RFC_7516_JWK)
        jwe = JWE(key, "A128KW", "A128CBC-HS256")
        assert jwe.decrypt(RFC_7516_JWE) == b"Live long and prosper."
