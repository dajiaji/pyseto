from secrets import token_bytes

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

from pyseto import DecryptError, Key, NotSupportedError
from pyseto.key_interface import KeyInterface
from pyseto.utils import base64url_decode, base64url_encode

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
        "version",
        [
            1,
            3,
        ],
    )
    def test_key_from_paserk_for_local_pw_with_excessive_iterations(self, version):
        # A `local-pw` PASERK carries the PBKDF2 iteration count (4 bytes at
        # offset 32) in the clear. An attacker-supplied blob must not be able to
        # trigger an unbounded KDF before the MAC is checked.
        k = Key.new(version, "local", token_bytes(32))
        wpk = k.to_paserk(password="correct horse battery staple")
        h, _, body = wpk.rpartition(".")
        d = bytearray(base64url_decode(body))
        d[32:36] = (0xFFFFFFFF).to_bytes(4, byteorder="big")
        tampered = h + "." + base64url_encode(bytes(d)).decode("utf-8")
        with pytest.raises(ValueError) as err:
            Key.from_paserk(tampered, password="correct horse battery staple")
            pytest.fail("Key.from_paserk() should fail.")
        assert "PBKDF2 iteration count" in str(err.value)

    @pytest.mark.parametrize(
        "version",
        [
            2,
            4,
        ],
    )
    def test_key_from_paserk_for_local_pw_with_excessive_memory(self, version):
        # A `local-pw` PASERK carries the Argon2 memory cost (8 bytes at offset
        # 16) in the clear. An attacker-supplied blob must not be able to request
        # a huge allocation before the MAC is checked.
        k = Key.new(version, "local", token_bytes(32))
        wpk = k.to_paserk(password="correct horse battery staple")
        h, _, body = wpk.rpartition(".")
        d = bytearray(base64url_decode(body))
        d[16:24] = (0xFFFFFFFFFFFFFFFF).to_bytes(8, byteorder="big")
        tampered = h + "." + base64url_encode(bytes(d)).decode("utf-8")
        with pytest.raises(ValueError) as err:
            Key.from_paserk(tampered, password="correct horse battery staple")
            pytest.fail("Key.from_paserk() should fail.")
        assert "Argon2 memory cost" in str(err.value)

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
        "version, pub, priv",
        [
            (1, "keys/public_key_rsa_4096.pem", "keys/private_key_rsa_4096.pem"),
            (3, "keys/public_key_ecdsa_p384.pem", "keys/private_key_ecdsa_p384.pem"),
        ],
    )
    def test_key_to_paserk_seal_roundtrip(self, version, pub, priv):
        k = Key.new(version, "local", token_bytes(32))
        sealed = k.to_paserk(sealing_key=load_key(pub))
        assert sealed.startswith(f"k{version}.seal.")
        unsealed = Key.from_paserk(sealed, unsealing_key=load_key(priv))
        assert k._key == unsealed._key

    @pytest.mark.parametrize(
        "version, pub",
        [
            (1, "keys/public_key_rsa_4096.pem"),
            (2, "keys/public_key_x25519.pem"),
            (3, "keys/public_key_ecdsa_p384.pem"),
            (4, "keys/public_key_x25519.pem"),
        ],
    )
    def test_key_to_paserk_with_password_and_sealing_key(self, version, pub):
        k = Key.new(version, "local", token_bytes(32))
        with pytest.raises(ValueError) as err:
            k.to_paserk(password="password", sealing_key=load_key(pub))
            pytest.fail("to_paserk() should fail.")
        assert "Only one of wrapping_key, password or sealing_key should be specified." in str(err.value)

    @pytest.mark.parametrize(
        "version",
        [
            1,
            2,
            3,
            4,
        ],
    )
    def test_key_from_paserk_for_seal_without_unsealing_key(self, version):
        with pytest.raises(ValueError) as err:
            Key.from_paserk(f"k{version}.seal.AAAAAAAAAAAAAAAA")
            pytest.fail("Key.from_paserk should fail.")
        assert "seal needs unsealing_key." in str(err.value)

    @pytest.mark.parametrize(
        "version, priv",
        [
            (1, "keys/private_key_rsa_4096.pem"),
            (3, "keys/private_key_ecdsa_p384.pem"),
        ],
    )
    def test_key_from_paserk_with_unsealing_key_for_wrong_paserk_type(self, version, priv):
        with pytest.raises(ValueError) as err:
            Key.from_paserk(f"k{version}.local.AAAAAAAAAAAAAAAA", unsealing_key=load_key(priv))
            pytest.fail("Key.from_paserk should fail.")
        assert "Invalid PASERK type: local." in str(err.value)

    @pytest.mark.parametrize(
        "version",
        [
            1,
            3,
        ],
    )
    @pytest.mark.parametrize(
        "unsealing_key",
        [
            b"not-pem",
            b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
        ],
    )
    def test_key_from_paserk_seal_with_invalid_pem(self, version, unsealing_key):
        with pytest.raises(ValueError) as err:
            Key.from_paserk(f"k{version}.seal.AAAAAAAAAAAAAAAA", unsealing_key=unsealing_key)
            pytest.fail("Key.from_paserk should fail.")
        assert "Invalid or unsupported PEM format." in str(err.value)

    @pytest.mark.parametrize(
        "version, priv, msg",
        [
            (1, "keys/private_key_ecdsa_p384.pem", "The unsealing key is not RSA key."),
            (1, "keys/private_key_rsa.pem", "The unsealing key must be 4096-bit RSA key."),
            (3, "keys/private_key_rsa_4096.pem", "The unsealing key is not P-384 key."),
        ],
    )
    def test_key_from_paserk_seal_with_wrong_unsealing_key(self, version, priv, msg):
        with pytest.raises(ValueError) as err:
            Key.from_paserk(f"k{version}.seal.AAAAAAAAAAAAAAAA", unsealing_key=load_key(priv))
            pytest.fail("Key.from_paserk should fail.")
        assert msg in str(err.value)

    def test_key_from_paserk_seal_v3_with_wrong_curve_unsealing_key(self):
        sk = ec.generate_private_key(ec.SECP256R1())
        pem = sk.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        with pytest.raises(ValueError) as err:
            Key.from_paserk("k3.seal.AAAAAAAAAAAAAAAA", unsealing_key=pem)
            pytest.fail("Key.from_paserk should fail.")
        assert "The unsealing key is not P-384 key." in str(err.value)

    @pytest.mark.parametrize(
        "version, priv",
        [
            (1, "keys/private_key_rsa_4096.pem"),
            (3, "keys/private_key_ecdsa_p384.pem"),
        ],
    )
    def test_key_from_paserk_seal_with_invalid_payload_length(self, version, priv):
        paserk = f"k{version}.seal." + base64url_encode(b"0" * 64).decode("utf-8")
        with pytest.raises(ValueError) as err:
            Key.from_paserk(paserk, unsealing_key=load_key(priv))
            pytest.fail("Key.from_paserk should fail.")
        assert "Invalid PASERK format." in str(err.value)

    def test_key_from_paserk_seal_v1_with_out_of_range_ciphertext(self):
        private_key = serialization.load_pem_private_key(
            load_key("keys/private_key_rsa_4096.pem").encode("utf-8"),
            password=None,
        )
        n = private_key.private_numbers().public_numbers.n
        payload = b"0" * 48 + b"0" * 32 + n.to_bytes(512, byteorder="big")
        paserk = "k1.seal." + base64url_encode(payload).decode("utf-8")
        with pytest.raises(ValueError) as err:
            Key.from_paserk(paserk, unsealing_key=load_key("keys/private_key_rsa_4096.pem"))
            pytest.fail("Key.from_paserk should fail.")
        assert "Invalid PASERK format." in str(err.value)

    @pytest.mark.parametrize(
        "version, pub, msg",
        [
            (1, "keys/public_key_ecdsa_p384.pem", "The sealing key is not RSA key."),
            (1, "keys/public_key_rsa.pem", "The sealing key must be 4096-bit RSA key."),
            (3, "keys/public_key_rsa_4096.pem", "The sealing key is not P-384 key."),
        ],
    )
    def test_key_to_paserk_seal_with_wrong_sealing_key(self, version, pub, msg):
        k = Key.new(version, "local", token_bytes(32))
        with pytest.raises(ValueError) as err:
            k.to_paserk(sealing_key=load_key(pub))
            pytest.fail("to_paserk() should fail.")
        assert msg in str(err.value)

    def test_key_to_paserk_seal_v1_with_wrong_public_exponent(self):
        public_key = serialization.load_pem_public_key(load_key("keys/public_key_rsa_4096.pem").encode("utf-8"))
        bad_public_key = RSAPublicNumbers(3, public_key.public_numbers().n).public_key()
        pem = bad_public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        k = Key.new(1, "local", token_bytes(32))
        with pytest.raises(ValueError) as err:
            k.to_paserk(sealing_key=pem)
            pytest.fail("to_paserk() should fail.")
        assert "The RSA public exponent must be 65537." in str(err.value)

    def test_key_to_paserk_seal_v3_with_wrong_curve_sealing_key(self):
        pk = ec.generate_private_key(ec.SECP256R1()).public_key()
        pem = pk.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        k = Key.new(3, "local", token_bytes(32))
        with pytest.raises(ValueError) as err:
            k.to_paserk(sealing_key=pem)
            pytest.fail("to_paserk() should fail.")
        assert "The sealing key is not P-384 key." in str(err.value)

    @pytest.mark.parametrize(
        "version",
        [
            1,
            3,
        ],
    )
    @pytest.mark.parametrize(
        "sealing_key",
        [
            "not-pem",
            "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
        ],
    )
    def test_key_to_paserk_seal_with_invalid_pem(self, version, sealing_key):
        k = Key.new(version, "local", token_bytes(32))
        with pytest.raises(ValueError) as err:
            k.to_paserk(sealing_key=sealing_key)
            pytest.fail("to_paserk() should fail.")
        assert "Invalid or unsupported PEM format." in str(err.value)

    @pytest.mark.parametrize(
        "version, key",
        [
            (1, load_key("keys/public_key_rsa.pem")),
            (2, load_key("keys/public_key_ed25519.pem")),
            (3, load_key("keys/public_key_ecdsa_p384.pem")),
            (4, load_key("keys/public_key_ed25519.pem")),
        ],
    )
    def test_key_to_paserk_seal_for_public_key(self, version, key):
        k = Key.new(version, "public", key)
        with pytest.raises(ValueError) as err:
            k.to_paserk(sealing_key="xxx")
            pytest.fail("to_paserk() should fail.")
        assert "Key sealing can only be used for local key." in str(err.value)

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
