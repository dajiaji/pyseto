from secrets import token_bytes

import pytest

import pyseto
from pyseto import DecryptError, EncryptError, Key, VerifyError
from pyseto.versions.v2 import V2Local, V2Public

from .utils import load_key


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
    def test_v2_local_new_with_invalid_arg(self, key, msg):
        with pytest.raises(ValueError) as err:
            Key.new(2, "local", key)
            pytest.fail("Key.new() should fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "key",
        [
            None,
            0,
            token_bytes(65),
        ],
    )
    def test_v2_local__generate_hash_with_invalid_arg(self, key):
        with pytest.raises(EncryptError) as err:
            V2Local._generate_hash(key, b"Hello world!", 32)
            pytest.fail("V2Local._generate_hash() should fail.")
        assert "Failed to generate hash." in str(err.value)

    @pytest.mark.parametrize(
        "ptk",
        [
            None,
            0,
        ],
    )
    def test_v2_local__encode_pie_with_invalid_ptk(self, ptk):
        with pytest.raises(EncryptError) as err:
            V2Local._encode_pie("v2.local-wrap.pie.", token_bytes(32), ptk)
            pytest.fail("V2Local._encode_pie() should fail.")
        assert "Failed to encrypt." in str(err.value)

    def test_v2_local_decrypt_via_decode_with_wrong_key(self):
        k1 = Key.new(2, "local", token_bytes(32))
        k2 = Key.new(2, "local", token_bytes(32))
        token = pyseto.encode(k1, b"Hello world!")
        with pytest.raises(DecryptError) as err:
            pyseto.decode(k2, token)
            pytest.fail("pyseto.decode() should fail.")
        assert "Failed to decrypt." in str(err.value)

    def test_v2_local_encrypt_with_invalid_arg(self):
        k = Key.new(2, "local", token_bytes(32))
        with pytest.raises(EncryptError) as err:
            k.encrypt(None)
            pytest.fail("pyseto.encrypt() should fail.")
        assert "Failed to generate internal nonce." in str(err.value)

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
    def test_v2_local_encrypt_via_encode_with_wrong_nonce(self, nonce):
        k = Key.new(2, "local", token_bytes(32))
        with pytest.raises(ValueError) as err:
            pyseto.encode(k, b"Hello world!", nonce=nonce)
            pytest.fail("pyseto.encode() should fail.")
        assert "nonce must be 24 bytes long." in str(err.value)

    @pytest.mark.parametrize(
        "paserk, msg",
        [
            ("xx.local.AAAAAAAAAAAAAAAA", "Invalid PASERK version: xx."),
            ("k3.local.AAAAAAAAAAAAAAAA", "Invalid PASERK version: k3."),
            ("k2.local.xxx.AAAAAAAAAAAAAAAA", "Invalid PASERK format."),
            ("k2.public.xxx.AAAAAAAAAAAAAAAA", "Invalid PASERK format."),
            ("k2.xxx.AAAAAAAAAAAAAAAA", "Invalid PASERK type: xxx."),
            ("k2.public.AAAAAAAAAAAAAAAA", "Invalid PASERK type: public."),
            (
                "k2.local-wrap.AAAAAAAAAAAAAAAA",
                "local-wrap needs wrapping_key.",
            ),
            (
                "k2.secret-wrap.AAAAAAAAAAAAAAAA",
                "Invalid PASERK type: secret-wrap.",
            ),
            (
                "k2.local-pw.AAAAAAAAAAAAAAAA",
                "local-pw needs password.",
            ),
        ],
    )
    def test_v2_local_from_paserk_with_invalid_args(self, paserk, msg):

        with pytest.raises(ValueError) as err:
            V2Local.from_paserk(paserk)
            pytest.fail("Key.from_paserk should fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "paserk, msg",
        [
            ("xx.local-wrap.AAAAAAAAAAAAAAAA", "Invalid PASERK version: xx."),
            ("k2.local-wrap.AAAAAAAAAAAAAAAA", "Invalid PASERK format."),
            ("k2.local-wrap.xxx.AAAAAAAAAAAAAAAA", "Unknown wrapping algorithm: xxx."),
            ("k2.xxx.pie.AAAAAAAAAAAAAAAA", "Invalid PASERK type: xxx."),
        ],
    )
    def test_v2_local_from_paserk_with_wrapping_key_and_invalid_args(self, paserk, msg):

        with pytest.raises(ValueError) as err:
            V2Local.from_paserk(paserk, wrapping_key=token_bytes(32))
            pytest.fail("Key.from_paserk should fail.")
        assert msg in str(err.value)


class TestV2Public:
    """
    Tests for v2.public.
    """

    def test_v2_public_verify_via_encode_with_wrong_key(self):
        sk = Key.new(2, "public", load_key("keys/private_key_ed25519.pem"))
        pk = Key.new(2, "public", load_key("keys/public_key_ed25519_2.pem"))
        token = pyseto.encode(sk, b"Hello world!")
        with pytest.raises(VerifyError) as err:
            pyseto.decode(pk, token)
            pytest.fail("pyseto.decode() should fail.")
        assert "Failed to verify." in str(err.value)

    @pytest.mark.parametrize(
        "paserk, msg",
        [
            ("xx.public.AAAAAAAAAAAAAAAA", "Invalid PASERK version: xx."),
            ("k3.public.AAAAAAAAAAAAAAAA", "Invalid PASERK version: k3."),
            ("k2.public.xxx.AAAAAAAAAAAAAAAA", "Invalid PASERK format."),
            ("k2.local.xxx.AAAAAAAAAAAAAAAA", "Invalid PASERK format."),
            ("k2.xxx.AAAAAAAAAAAAAAAA", "Invalid PASERK type: xxx."),
            ("k2.local.AAAAAAAAAAAAAAAA", "Invalid PASERK type: local."),
            (
                "k2.local-wrap.AAAAAAAAAAAAAAAA",
                "Invalid PASERK type: local-wrap.",
            ),
            (
                "k2.secret-wrap.AAAAAAAAAAAAAAAA",
                "secret-wrap needs wrapping_key.",
            ),
            (
                "k2.secret-pw.AAAAAAAAAAAAAAAA",
                "secret-pw needs password.",
            ),
        ],
    )
    def test_v2_public_from_paserk_with_invalid_args(self, paserk, msg):

        with pytest.raises(ValueError) as err:
            V2Public.from_paserk(paserk)
            pytest.fail("Key.from_paserk should fail.")
        assert msg in str(err.value)
