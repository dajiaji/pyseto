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
                "v1",
                load_key("keys/public_key_rsa.pem"),
                "A public key cannot be used for signing.",
            ),
            (
                "v2",
                load_key("keys/public_key_ed25519.pem"),
                "A public key cannot be used for signing.",
            ),
            (
                "v3",
                load_key("keys/public_key_ecdsa_p384.pem"),
                "A public key cannot be used for signing.",
            ),
            (
                "v4",
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
            ("v1", load_key("keys/public_key_rsa.pem"), "Invalid payload."),
            ("v2", load_key("keys/public_key_ed25519.pem"), "Invalid payload."),
            ("v3", load_key("keys/public_key_ecdsa_p384.pem"), "Invalid payload."),
            ("v4", load_key("keys/public_key_ed25519.pem"), "Invalid payload."),
        ],
    )
    def test_decode_with_invalid_payload(self, version, key, msg):
        k = Key.new(version, "public", key)
        with pytest.raises(ValueError) as err:
            pyseto.decode(k, version + ".public.11111111")
            pytest.fail("pyseto.decode() should fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "version, public_key",
        [
            ("v1", load_key("keys/public_key_rsa.pem")),
            ("v2", load_key("keys/public_key_ed25519.pem")),
            ("v3", load_key("keys/public_key_ecdsa_p384.pem")),
        ],
    )
    def test_decode_with_another_version_key(self, version, public_key):
        sk = Key.new("v4", "public", load_key("keys/private_key_ed25519.pem"))
        pk = Key.new(version, "public", public_key)
        token = pyseto.encode(sk, "Hello world!")
        with pytest.raises(ValueError) as err:
            pyseto.decode(pk, token)
            pytest.fail("pyseto.decode() should fail.")
        assert "key is not found for verifying the token." in str(err.value)

    def test_decode_with_empty_list_of_keys(self):
        sk = Key.new("v4", "public", load_key("keys/private_key_ed25519.pem"))
        token = pyseto.encode(sk, "Hello world!")
        with pytest.raises(ValueError) as err:
            pyseto.decode([], token)
            pytest.fail("pyseto.decode() should fail.")
        assert "key is not found for verifying the token." in str(err.value)

    def test_decode_with_different_keys(self):
        sk = Key.new("v4", "public", load_key("keys/private_key_ed25519.pem"))
        pk1 = Key.new("v1", "public", load_key("keys/public_key_rsa.pem"))
        pk2 = Key.new("v2", "public", load_key("keys/public_key_ed25519.pem"))
        pk3 = Key.new("v3", "public", load_key("keys/public_key_ecdsa_p384.pem"))
        token = pyseto.encode(sk, "Hello world!")
        with pytest.raises(ValueError) as err:
            pyseto.decode([pk1, pk2, pk3], token)
            pytest.fail("pyseto.decode() should fail.")
        assert "key is not found for verifying the token." in str(err.value)

    def test_decode_with_multiple_keys(self):
        sk = Key.new("v4", "public", load_key("keys/private_key_ed25519.pem"))
        token = pyseto.encode(sk, b"Hello world!")
        pk1 = Key.new("v1", "public", load_key("keys/public_key_rsa.pem"))
        pk2 = Key.new("v2", "public", load_key("keys/public_key_ed25519.pem"))
        pk3 = Key.new("v3", "public", load_key("keys/public_key_ecdsa_p384.pem"))
        pk4 = Key.new("v4", "public", load_key("keys/public_key_ed25519.pem"))
        decoded = pyseto.decode([pk1, pk2, pk3, pk4], token)
        assert decoded.payload == b"Hello world!"

    def test_decode_with_multiple_keys_have_same_header(self):
        sk = Key.new("v4", "public", load_key("keys/private_key_ed25519.pem"))
        token = pyseto.encode(sk, b"Hello world!")
        pk2 = Key.new("v4", "public", load_key("keys/public_key_ed25519_2.pem"))
        pk1 = Key.new("v4", "public", load_key("keys/public_key_ed25519.pem"))
        decoded = pyseto.decode([pk2, pk1], token)
        assert decoded.payload == b"Hello world!"
