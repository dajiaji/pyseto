from secrets import token_bytes

import pytest

from pyseto import DecryptError, Key, NotSupportedError
from pyseto.key_interface import KeyInterface
from pyseto.utils import base64url_decode

from .utils import load_jwk, load_key


class TestKey:
    """
    Tests for Key.
    """

    @pytest.mark.parametrize(
        "version, purpose, key",
        [
            (1, "local", token_bytes(32)),
            (2, "local", token_bytes(32)),
            (3, "local", token_bytes(32)),
            (4, "local", token_bytes(32)),
        ],
    )
    def test_key_new_local(self, version, purpose, key):
        k = Key.new(version, purpose, key)
        assert isinstance(k, KeyInterface)
        assert k.version == version
        assert k.purpose == purpose
        with pytest.raises(NotSupportedError) as err:
            k.sign(b"Hello world!")
            pytest.fail("Key.sign() should fail.")
        assert "A key for local does not have sign()." in str(err.value)
        with pytest.raises(NotSupportedError) as err:
            k.verify(b"xxxxxx")
            pytest.fail("Key.verify() should fail.")
        assert "A key for local does not have verify()." in str(err.value)

    @pytest.mark.parametrize(
        "version, purpose, key",
        [
            (1, "public", load_key("keys/private_key_rsa.pem")),
            (1, "public", load_key("keys/public_key_rsa.pem")),
            (2, "public", load_key("keys/private_key_ed25519.pem")),
            (2, "public", load_key("keys/public_key_ed25519.pem")),
            (3, "public", load_key("keys/private_key_ecdsa_p384.pem")),
            (3, "public", load_key("keys/public_key_ecdsa_p384.pem")),
            (4, "public", load_key("keys/private_key_ed25519.pem")),
            (4, "public", load_key("keys/public_key_ed25519.pem")),
        ],
    )
    def test_key_new_public(self, version, purpose, key):
        k = Key.new(version, purpose, key)
        assert isinstance(k, KeyInterface)
        assert k.version == version
        assert k.purpose == purpose
        with pytest.raises(NotSupportedError) as err:
            k.encrypt(b"Hello world!")
            pytest.fail("Key.sign() should fail.")
        assert "A key for public does not have encrypt()." in str(err.value)
        with pytest.raises(NotSupportedError) as err:
            k.decrypt(b"xxxxxx")
            pytest.fail("Key.verify() should fail.")
        assert "A key for public does not have decrypt()." in str(err.value)

    @pytest.mark.parametrize(
        "version, key, msg",
        [
            (1, load_key("keys/private_key_ed25519.pem"), "The key is not RSA key."),
            (1, load_key("keys/public_key_ed25519.pem"), "The key is not RSA key."),
            (
                1,
                load_key("keys/private_key_ecdsa_p384.pem"),
                "The key is not RSA key.",
            ),
            (
                1,
                load_key("keys/public_key_ecdsa_p384.pem"),
                "The key is not RSA key.",
            ),
            (2, load_key("keys/private_key_rsa.pem"), "The key is not Ed25519 key."),
            (2, load_key("keys/public_key_rsa.pem"), "The key is not Ed25519 key."),
            (
                2,
                load_key("keys/private_key_ecdsa_p384.pem"),
                "The key is not Ed25519 key.",
            ),
            (
                2,
                load_key("keys/public_key_ecdsa_p384.pem"),
                "The key is not Ed25519 key.",
            ),
            (
                3,
                load_key("keys/private_key_ed25519.pem"),
                "The key is not ECDSA key.",
            ),
            (
                3,
                load_key("keys/public_key_ed25519.pem"),
                "The key is not ECDSA key.",
            ),
            (3, load_key("keys/private_key_rsa.pem"), "The key is not ECDSA key."),
            (3, load_key("keys/public_key_rsa.pem"), "The key is not ECDSA key."),
            (4, load_key("keys/private_key_rsa.pem"), "The key is not Ed25519 key."),
            (4, load_key("keys/public_key_rsa.pem"), "The key is not Ed25519 key."),
            (
                4,
                load_key("keys/private_key_ecdsa_p384.pem"),
                "The key is not Ed25519 key.",
            ),
            (
                4,
                load_key("keys/public_key_ecdsa_p384.pem"),
                "The key is not Ed25519 key.",
            ),
        ],
    )
    def test_key_new_public_with_wrong_key(self, version, key, msg):
        with pytest.raises(ValueError) as err:
            Key.new(version, "public", key)
            pytest.fail("Key.new should fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "version, purpose, key, msg",
        [
            ("v*", "local", token_bytes(32), "Invalid version: v*."),
            ("v0", "local", token_bytes(32), "Invalid version: v0."),
            (0, "local", token_bytes(32), "Invalid version: 0."),
            (
                "v*",
                "public",
                load_key("keys/private_key_rsa.pem"),
                "Invalid version: v*.",
            ),
            (
                "v0",
                "public",
                load_key("keys/private_key_rsa.pem"),
                "Invalid version: v0.",
            ),
            (
                0,
                "public",
                load_key("keys/private_key_rsa.pem"),
                "Invalid version: 0.",
            ),
            (1, "xxx", token_bytes(32), "Invalid purpose: xxx."),
            (1, "public", "-----BEGIN BAD", "Invalid or unsupported PEM format."),
        ],
    )
    def test_key_new_with_invalid_arg(self, version, purpose, key, msg):
        with pytest.raises(ValueError) as err:
            Key.new(version, purpose, key)
            pytest.fail("Key.new should fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "version, key",
        [
            # (1, load_jwk("keys/private_key_rsa.json")),
            # (1, load_jwk("keys/public_key_rsa.json")),
            (2, load_jwk("keys/private_key_ed25519.json")),
            (2, load_jwk("keys/public_key_ed25519.json")),
            (3, load_jwk("keys/private_key_ecdsa_p384.json")),
            (3, load_jwk("keys/public_key_ecdsa_p384.json")),
            (4, load_jwk("keys/private_key_ed25519.json")),
            (4, load_jwk("keys/public_key_ed25519.json")),
        ],
    )
    def test_key_from_asymmetric_params(self, version, key):

        k = Key.from_asymmetric_key_params(version, x=key["x"], y=key["y"], d=key["d"])
        assert isinstance(k, KeyInterface)
        assert k.version == version
        assert k.purpose == "public"

    @pytest.mark.parametrize(
        "paserk",
        [
            "k1.local.AAAAAAAAAAAAAAAA",
            "k1.public.AAAAAAAAAAAAAAAA",
            "k2.local.AAAAAAAAAAAAAAAA",
            "k2.public.AAAAAAAAAAAAAAAA",
            "k3.local.AAAAAAAAAAAAAAAA",
            "k3.public.AAAAAAAAAAAAAAAA",
            "k4.local.AAAAAAAAAAAAAAAA",
            "k4.public.AAAAAAAAAAAAAAAA",
        ],
    )
    def test_key_from_paserk_with_wrapping_key_and_password(self, paserk):

        with pytest.raises(ValueError) as err:
            Key.from_paserk(paserk, wrapping_key="xxx", password="yyy")
            pytest.fail("Key.from_paserk should fail.")
        assert "Only one of wrapping_key or password should be specified." in str(err.value)

    @pytest.mark.parametrize(
        "paserk, msg",
        [
            ("k1.local.AAAAAAAAAAAAAAAA", "Invalid PASERK type: local."),
            ("k1.public.AAAAAAAAAAAAAAAA", "Invalid PASERK type: public."),
            ("k2.local.AAAAAAAAAAAAAAAA", "Invalid PASERK type: local."),
            ("k2.public.AAAAAAAAAAAAAAAA", "Invalid PASERK type: public."),
            ("k3.local.AAAAAAAAAAAAAAAA", "Invalid PASERK type: local."),
            ("k3.public.AAAAAAAAAAAAAAAA", "Invalid PASERK type: public."),
            ("k4.local.AAAAAAAAAAAAAAAA", "Invalid PASERK type: local."),
            ("k4.public.AAAAAAAAAAAAAAAA", "Invalid PASERK type: public."),
        ],
    )
    def test_key_from_paserk_with_password_for_wrong_paserk(self, paserk, msg):

        with pytest.raises(ValueError) as err:
            Key.from_paserk(paserk, password="yyy")
            pytest.fail("Key.from_paserk should fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "paserk, msg",
        [
            ("v1.local.AAAAAAAAAAAAAAAA", "Invalid PASERK version: v1."),
            ("*.local.AAAAAAAAAAAAAAAA", "Invalid PASERK version: *."),
            ("k1.xxx.AAAAAAAAAAAAAAAA", "Invalid PASERK key type: xxx."),
        ],
    )
    def test_key_from_paserk_with_invalid_args(self, paserk, msg):

        with pytest.raises(ValueError) as err:
            Key.from_paserk(paserk)
            pytest.fail("Key.from_paserk should fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "version",
        [
            1,
            2,
            3,
            4,
        ],
    )
    def test_key_from_paserk_for_local_with_wrong_wrapping_key(self, version):
        k = Key.new(version, "local", token_bytes(32))
        wk1 = token_bytes(32)
        wk2 = token_bytes(32)
        wpk = k.to_paserk(wrapping_key=wk1)
        with pytest.raises(DecryptError) as err:
            Key.from_paserk(wpk, wrapping_key=wk2)
            pytest.fail("Key.from_paserk() should fail.")
        assert "Failed to unwrap a key." in str(err.value)

    @pytest.mark.parametrize(
        "version",
        [
            1,
            2,
            3,
            4,
        ],
    )
    def test_key_from_paserk_for_local_with_wrong_password(self, version):
        k = Key.new(version, "local", token_bytes(32))
        wk1 = token_bytes(32)
        wk2 = token_bytes(32)
        wpk = k.to_paserk(password=wk1)
        with pytest.raises(DecryptError) as err:
            Key.from_paserk(wpk, password=wk2)
            pytest.fail("Key.from_paserk() should fail.")
        assert "Failed to unwrap a key." in str(err.value)

    @pytest.mark.parametrize(
        "version, key",
        [
            (1, load_key("keys/private_key_rsa.pem")),
            (2, load_key("keys/private_key_ed25519.pem")),
            (3, load_key("keys/private_key_ecdsa_p384.pem")),
            (4, load_key("keys/private_key_ed25519.pem")),
        ],
    )
    def test_key_from_paserk_for_private_key_with_wrong_wrapping_key(self, version, key):
        k = Key.new(version, "public", key)
        wk1 = token_bytes(32)
        wk2 = token_bytes(32)
        wpk = k.to_paserk(wrapping_key=wk1)
        with pytest.raises(DecryptError) as err:
            Key.from_paserk(wpk, wrapping_key=wk2)
            pytest.fail("Key.from_paserk() should fail.")
        assert "Failed to unwrap a key." in str(err.value)

    @pytest.mark.parametrize(
        "version, key",
        [
            (1, load_key("keys/public_key_rsa.pem")),
            (2, load_key("keys/public_key_ed25519.pem")),
            (3, load_key("keys/public_key_ecdsa_p384.pem")),
            (4, load_key("keys/public_key_ed25519.pem")),
        ],
    )
    def test_key_from_paserk_for_public_key_with_wrapping_key(self, version, key):
        k = Key.new(version, "public", key)
        wk = token_bytes(32)
        with pytest.raises(ValueError) as err:
            k.to_paserk(wrapping_key=wk)
            pytest.fail("to_paserk() should fail.")
        assert "Public key cannot be wrapped." in str(err.value)

    @pytest.mark.parametrize(
        "version, key",
        [
            (1, load_key("keys/public_key_rsa.pem")),
            (2, load_key("keys/public_key_ed25519.pem")),
            (3, load_key("keys/public_key_ecdsa_p384.pem")),
            (4, load_key("keys/public_key_ed25519.pem")),
        ],
    )
    def test_key_from_paserk_for_public_key_with_password(self, version, key):
        k = Key.new(version, "public", key)
        wk = token_bytes(32)
        with pytest.raises(ValueError) as err:
            k.to_paserk(password=wk)
            pytest.fail("to_paserk() should fail.")
        assert "Public key cannot be wrapped." in str(err.value)

    @pytest.mark.parametrize(
        "version, key, msg",
        [
            (
                1,
                load_jwk("keys/private_key_rsa.json"),
                "v1.public is not supported on from_key_parameters.",
            ),
            (999, load_jwk("keys/private_key_ed25519.json"), "Invalid version: 999."),
            (0, load_jwk("keys/private_key_ed25519.json"), "Invalid version: 0."),
            (
                2,
                {"x": b"xxx", "y": b"", "d": b"ddd"},
                "Only one of x or d should be set for v2.public.",
            ),
            (2, {"x": b"xxx", "y": b"", "d": b""}, "Failed to load key."),
            (2, {"x": b"", "y": b"", "d": b"ddd"}, "Failed to load key."),
            (
                2,
                {"x": b"", "y": b"", "d": b""},
                "x or d should be set for v2.public.",
            ),
            (
                3,
                {"x": b"xxx", "y": b"", "d": b"ddd"},
                "x and y (and d) should be set for v3.public.",
            ),
            (
                3,
                {"x": b"", "y": b"yyy", "d": b"ddd"},
                "x and y (and d) should be set for v3.public.",
            ),
            (3, {"x": b"xxx", "y": b"yyy", "d": b""}, "Failed to load key."),
            (
                3,
                {
                    "x": base64url_decode("_XyN9woHaS0mPimSW-etwJMEDSzxIMjp4PjezavU8SHJoClz1bQrcmPb1ZJxHxhI"),
                    "y": base64url_decode("GCNfc32p9sRotx7u2oDGJ3Eqz6q5zPHLdizNn83oRsUTN31eCWfGLHWRury3xF50"),
                    "d": b"ddd",
                },
                "Failed to load key.",
            ),
            (
                4,
                {"x": b"xxx", "y": b"", "d": b"ddd"},
                "Only one of x or d should be set for v4.public.",
            ),
            (4, {"x": b"xxx", "y": b"", "d": b""}, "Failed to load key."),
            (4, {"x": b"", "y": b"", "d": b"ddd"}, "Failed to load key."),
            (
                4,
                {"x": b"", "y": b"", "d": b""},
                "x or d should be set for v4.public.",
            ),
        ],
    )
    def test_key_from_asymmetric_params_with_invalid_arg(self, version, key, msg):

        with pytest.raises(ValueError) as err:
            Key.from_asymmetric_key_params(version, x=key["x"], y=key["y"], d=key["d"])
            pytest.fail("Key.from_asymmetric_key_params() should fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "version, purpose, key",
        [
            (1, "public", load_key("keys/public_key_rsa.pem")),
            (2, "public", load_key("keys/public_key_ed25519.pem")),
            (3, "public", load_key("keys/public_key_ecdsa_p384.pem")),
            (4, "public", load_key("keys/public_key_ed25519.pem")),
        ],
    )
    def test_key_to_paserk_public(self, version, purpose, key):
        k = Key.new(version, purpose, key)
        assert k.to_paserk().startswith(f"k{k.version}.public.")

    @pytest.mark.parametrize(
        "version, purpose, key",
        [
            (1, "public", load_key("keys/private_key_rsa.pem")),
            (2, "public", load_key("keys/private_key_ed25519.pem")),
            (3, "public", load_key("keys/private_key_ecdsa_p384.pem")),
            (4, "public", load_key("keys/private_key_ed25519.pem")),
        ],
    )
    def test_key_to_paserk_secret(self, version, purpose, key):
        k = Key.new(version, purpose, key)
        assert k.to_paserk().startswith(f"k{k.version}.secret.")

    @pytest.mark.parametrize(
        "version, purpose, key",
        [
            (1, "local", token_bytes(32)),
            (2, "local", token_bytes(32)),
            (3, "local", token_bytes(32)),
            (4, "local", token_bytes(32)),
            (1, "public", load_key("keys/private_key_rsa.pem")),
            (2, "public", load_key("keys/private_key_ed25519.pem")),
            (3, "public", load_key("keys/private_key_ecdsa_p384.pem")),
            (4, "public", load_key("keys/private_key_ed25519.pem")),
        ],
    )
    def test_key_to_paserk_secret_with_wrapping_key_and_password(self, version, purpose, key):
        k = Key.new(version, purpose, key)
        with pytest.raises(ValueError) as err:
            k.to_paserk(wrapping_key="xxx", password="yyy")
            pytest.fail("to_paserk() should fail.")
        assert "Only one of wrapping_key or password should be specified." in str(err.value)
