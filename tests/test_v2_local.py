from secrets import token_bytes

import pytest

import pyseto
from pyseto import DecryptError, Key


class TestV2Local:
    """
    Tests for v2.local.
    """

    @pytest.mark.parametrize(
        "key, msg",
        [
            (b"", "key must be specified."),
            (token_bytes(1), "key must be 32 bytes long."),
            (token_bytes(8), "key must be 32 bytes long."),
            (token_bytes(16), "key must be 32 bytes long."),
            (token_bytes(31), "key must be 32 bytes long."),
            (token_bytes(33), "key must be 32 bytes long."),
        ],
    )
    def test_v2_local_via_new_with_invalid_arg(self, key, msg):
        with pytest.raises(ValueError) as err:
            Key.new("v2", "local", key)
            pytest.fail("Key.new() should fail.")
        assert msg in str(err.value)

    def test_v2_local_via_decode_with_wrong_key(self):
        k1 = Key.new("v2", "local", token_bytes(32))
        k2 = Key.new("v2", "local", token_bytes(32))
        token = pyseto.encode(k1, b"Hello world!")
        with pytest.raises(DecryptError) as err:
            pyseto.decode(k2, token)
            pytest.fail("pyseto.decode() should fail.")
        assert "Failed to decrypt." in str(err.value)

    @pytest.mark.parametrize(
        "nonce",
        [
            token_bytes(1),
            token_bytes(8),
            token_bytes(23),
            token_bytes(25),
            token_bytes(32),
        ],
    )
    def test_v2_local_via_encode_with_wrong_nonce(self, nonce):
        k = Key.new("v2", "local", token_bytes(32))
        with pytest.raises(ValueError) as err:
            pyseto.encode(k, b"Hello world!", nonce=nonce)
            pytest.fail("pyseto.encode() should fail.")
        assert "nonce must be 24 bytes long." in str(err.value)
