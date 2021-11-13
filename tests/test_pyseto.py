import pytest

import pyseto
from pyseto import Key

from .utils import load_key


class InvalidSerializer:
    def __init__(self):
        self.dumps = "not a function."


class InvalidSerializer2:
    def dumps(self, *args):
        raise NotImplementedError("Not implemented")


class InvalidDeserializer:
    def __init__(self):
        self.loads = "not a function."


class InvalidDeserializer2:
    def loads(self, *args):
        raise NotImplementedError("Not implemented")


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
        "serializer, msg",
        [
            (
                None,
                "serializer should be specified for the payload object.",
            ),
            (
                {},
                "serializer should be specified for the payload object.",
            ),
            (
                [],
                "serializer should be specified for the payload object.",
            ),
            (
                "",
                "serializer should be specified for the payload object.",
            ),
            (
                b"",
                "serializer should be specified for the payload object.",
            ),
            (
                {"key": "value"},
                "serializer should have dumps().",
            ),
            (
                InvalidSerializer(),
                "serializer should have dumps().",
            ),
            (
                InvalidSerializer2(),
                "Failed to serialize the payload.",
            ),
        ],
    )
    def test_encode_object_payload_with_invalid_serializer(self, serializer, msg):
        private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"

        private_key = Key.new(version=4, purpose="public", key=private_key_pem)
        with pytest.raises(ValueError) as err:
            pyseto.encode(
                private_key,
                {
                    "data": "this is a signed message",
                    "exp": "2022-01-01T00:00:00+00:00",
                },
                serializer=serializer,
            )
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

    @pytest.mark.parametrize(
        "deserializer, msg",
        [
            (
                {"key": "value"},
                "deserializer should have loads().",
            ),
            (
                InvalidDeserializer(),
                "deserializer should have loads().",
            ),
            (
                InvalidDeserializer2(),
                "Failed to deserialize the payload.",
            ),
        ],
    )
    def test_decode_object_payload_with_invalid_deserializer(self, deserializer, msg):
        private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
        public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"
        private_key = Key.new(version=4, purpose="public", key=private_key_pem)
        token = pyseto.encode(
            private_key,
            {"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"},
        )
        public_key = Key.new(version=4, purpose="public", key=public_key_pem)
        with pytest.raises(ValueError) as err:
            pyseto.decode(public_key, token, deserializer=deserializer)
            pytest.fail("pyseto.decode() should fail.")
        assert msg in str(err.value)

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
