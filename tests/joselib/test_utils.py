import pytest

from joselib.exceptions import DecodeError
from joselib.utils import b64url_decode, b64url_encode, json_decode, json_encode


class TestB64Url:
    @pytest.mark.parametrize(
        "data", [b"", b"f", b"fo", b"foo", b"foob", b"\x00\xff\xfe"]
    )
    def test_round_trip(self, data: bytes) -> None:
        assert b64url_decode(b64url_encode(data)) == data

    def test_url_safe_alphabet(self) -> None:
        encoded = b64url_encode(b"\xfb\xef\xff")
        assert encoded == b"--__"
        assert b64url_decode(encoded) == b"\xfb\xef\xff"

    @pytest.mark.parametrize("data", [b"ab==", b"a+b0", b"a/b0", b"a b0", b"a.b0"])
    def test_rejects_invalid_characters(self, data: bytes) -> None:
        with pytest.raises(DecodeError):
            b64url_decode(data)

    @pytest.mark.parametrize("data", [b"a", b"abcda"])
    def test_rejects_invalid_length(self, data: bytes) -> None:
        with pytest.raises(DecodeError):
            b64url_decode(data)

    @pytest.mark.parametrize("data", [b"ab", b"aab", b"abcdab"])
    def test_rejects_non_canonical_encoding(self, data: bytes) -> None:
        with pytest.raises(DecodeError):
            b64url_decode(data)

    @pytest.mark.parametrize(("data", "expected"), [(b"aQ", b"i"), (b"aaw", b"i\xac")])
    def test_accepts_canonical_encoding(self, data: bytes, expected: bytes) -> None:
        assert b64url_decode(data) == expected


class TestJson:
    def test_round_trip(self) -> None:
        obj: dict[str, object] = {"b": 1, "a": [True, None, "x"]}
        assert json_decode(json_encode(obj)) == obj

    def test_encoding_is_compact_and_sorted(self) -> None:
        assert json_encode({"b": 1, "a": 2}) == b'{"a":2,"b":1}'

    def test_rejects_duplicate_keys(self) -> None:
        with pytest.raises(DecodeError):
            json_decode(b'{"a":1,"a":2}')

    def test_rejects_nested_duplicate_keys(self) -> None:
        with pytest.raises(DecodeError):
            json_decode(b'{"a":{"b":1,"b":2}}')

    @pytest.mark.parametrize("data", [b"", b"{", b"\xff"])
    def test_rejects_invalid_json(self, data: bytes) -> None:
        with pytest.raises(DecodeError):
            json_decode(data)

    @pytest.mark.parametrize("data", [b"[]", b"1", b'"a"', b"null"])
    def test_rejects_non_objects(self, data: bytes) -> None:
        with pytest.raises(DecodeError):
            json_decode(data)
