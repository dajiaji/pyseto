import pytest

import pyseto
from pyseto import Key

from .utils import load_key


class TestPyseto:
    """
    Tests for pyseto.encode and decode.
    """

    @pytest.mark.parametrize(
        "version, key, msg",
        [
            (
                1,
                load_key("keys/public_key_rsa.pem"),
                "A public key cannot be used for signing.",
            ),
            (
                2,
                load_key("keys/public_key_ed25519.pem"),
                "A public key cannot be used for signing.",
            ),
            (
                3,
                load_key("keys/public_key_ecdsa_p384.pem"),
                "A public key cannot be used for signing.",
            ),
            (
                4,
                load_key("keys/public_key_ed25519.pem"),
                "A public key cannot be used for signing.",
            ),
        ],
    )
    def test_encode_with_public_key(self, version, key, msg):
        k = Key.new(version, "public", key)
        with pytest.raises(ValueError) as err:
            pyseto.encode(k, b"Hello world!")
            pytest.fail("pyseto.encode() should fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "version, key, msg",
        [
            (1, load_key("keys/public_key_rsa.pem"), "Invalid payload."),
            (2, load_key("keys/public_key_ed25519.pem"), "Invalid payload."),
            (3, load_key("keys/public_key_ecdsa_p384.pem"), "Invalid payload."),
            (4, load_key("keys/public_key_ed25519.pem"), "Invalid payload."),
        ],
    )
    def test_decode_with_invalid_payload(self, version, key, msg):
        k = Key.new(version, "public", key)
        with pytest.raises(ValueError) as err:
            pyseto.decode(k, f"v{version}.public.11111111")
            pytest.fail("pyseto.decode() should fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "version, public_key",
        [
            (1, load_key("keys/public_key_rsa.pem")),
            (2, load_key("keys/public_key_ed25519.pem")),
            (3, load_key("keys/public_key_ecdsa_p384.pem")),
        ],
    )
    def test_decode_with_another_version_key(self, version, public_key):
        sk = Key.new(4, "public", load_key("keys/private_key_ed25519.pem"))
        pk = Key.new(version, "public", public_key)
        token = pyseto.encode(sk, "Hello world!")
        with pytest.raises(ValueError) as err:
            pyseto.decode(pk, token)
            pytest.fail("pyseto.decode() should fail.")
        assert "key is not found for verifying the token." in str(err.value)

    def test_decode_with_empty_list_of_keys(self):
        sk = Key.new(4, "public", load_key("keys/private_key_ed25519.pem"))
        token = pyseto.encode(sk, "Hello world!")
        with pytest.raises(ValueError) as err:
            pyseto.decode([], token)
            pytest.fail("pyseto.decode() should fail.")
        assert "key is not found for verifying the token." in str(err.value)

    def test_decode_with_different_keys(self):
        sk = Key.new(4, "public", load_key("keys/private_key_ed25519.pem"))
        pk1 = Key.new(1, "public", load_key("keys/public_key_rsa.pem"))
        pk2 = Key.new(2, "public", load_key("keys/public_key_ed25519.pem"))
        pk3 = Key.new(3, "public", load_key("keys/public_key_ecdsa_p384.pem"))
        token = pyseto.encode(sk, "Hello world!")
        with pytest.raises(ValueError) as err:
            pyseto.decode([pk1, pk2, pk3], token)
            pytest.fail("pyseto.decode() should fail.")
        assert "key is not found for verifying the token." in str(err.value)

    def test_decode_with_multiple_keys(self):
        sk = Key.new(4, "public", load_key("keys/private_key_ed25519.pem"))
        token = pyseto.encode(sk, b"Hello world!")
        pk1 = Key.new(1, "public", load_key("keys/public_key_rsa.pem"))
        pk2 = Key.new(2, "public", load_key("keys/public_key_ed25519.pem"))
        pk3 = Key.new(3, "public", load_key("keys/public_key_ecdsa_p384.pem"))
        pk4 = Key.new(4, "public", load_key("keys/public_key_ed25519.pem"))
        decoded = pyseto.decode([pk1, pk2, pk3, pk4], token)
        assert decoded.payload == b"Hello world!"

    def test_decode_with_multiple_keys_have_same_header(self):
        sk = Key.new(4, "public", load_key("keys/private_key_ed25519.pem"))
        token = pyseto.encode(sk, b"Hello world!")
        pk2 = Key.new(4, "public", load_key("keys/public_key_ed25519_2.pem"))
        pk1 = Key.new(4, "public", load_key("keys/public_key_ed25519.pem"))
        decoded = pyseto.decode([pk2, pk1], token)
        assert decoded.payload == b"Hello world!"
