from secrets import token_bytes

import pytest

import pyseto
from pyseto import DecryptError, EncryptError, Key, VerifyError
from pyseto.versions.v1 import V1Local, V1Public

from .utils import load_key


class TestV1Local:
    """
    Tests for v1.local.
    """

    @pytest.mark.parametrize(
        "key, msg",
        [
            (b"", "key must be specified."),
        ],
    )
    def test_v1_local_new_with_invalid_arg(self, key, msg):
        with pytest.raises(ValueError) as err:
            Key.new(1, "local", key)
            pytest.fail("Key.new() should fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "key",
        [
            None,
            0,
        ],
    )
    def test_v1_local__generate_hash_with_invalid_arg(self, key):
        with pytest.raises(EncryptError) as err:
            V1Local._generate_hash(key, b"Hello world!", 32)
            pytest.fail("V1Local._generate_hash() should fail.")
        assert "Failed to generate hash." in str(err.value)

    @pytest.mark.parametrize(
        "ptk",
        [
            None,
            0,
        ],
    )
    def test_v1_local__encode_pie_with_invalid_ptk(self, ptk):
        with pytest.raises(EncryptError) as err:
            V1Local._encode_pie("v1.local-wrap.pie.", token_bytes(32), ptk)
            pytest.fail("V1Local._encode_pie() should fail.")
        assert "Failed to encrypt." in str(err.value)

    def test_v1_local_decrypt_via_decode_with_wrong_key(self):
        k1 = Key.new(1, "local", b"our-secret")
        k2 = Key.new(1, "local", b"others-secret")
        token = pyseto.encode(k1, b"Hello world!")
        with pytest.raises(DecryptError) as err:
            pyseto.decode(k2, token)
            pytest.fail("pyseto.decode() should fail.")
        assert "Failed to decrypt." in str(err.value)

    def test_v1_local_encrypt_with_invalid_arg(self):
        k = Key.new(1, "local", b"our-secret")
        with pytest.raises(EncryptError) as err:
            k.encrypt(None)
            pytest.fail("pyseto.encrypt() should fail.")
        assert "Failed to encrypt." in str(err.value)

    @pytest.mark.parametrize(
        "nonce",
        [
            token_bytes(1),
            token_bytes(8),
            token_bytes(31),
            token_bytes(33),
            token_bytes(64),
        ],
    )
    def test_v1_local_encrypt_via_encode_with_wrong_nonce(self, nonce):
        k = Key.new(1, "local", b"our-secret")
        with pytest.raises(ValueError) as err:
            pyseto.encode(k, b"Hello world!", nonce=nonce)
            pytest.fail("pyseto.encode() should fail.")
        assert "nonce must be 32 bytes long." in str(err.value)

    @pytest.mark.parametrize(
        "paserk, msg",
        [
            ("xx.local.AAAAAAAAAAAAAAAA", "Invalid PASERK version: xx."),
            ("k2.local.AAAAAAAAAAAAAAAA", "Invalid PASERK version: k2."),
            ("k1.local.xxx.AAAAAAAAAAAAAAAA", "Invalid PASERK format."),
            ("k1.public.xxx.AAAAAAAAAAAAAAAA", "Invalid PASERK format."),
            ("k1.xxx.AAAAAAAAAAAAAAAA", "Invalid PASERK type: xxx."),
            ("k1.public.AAAAAAAAAAAAAAAA", "Invalid PASERK type: public."),
            (
                "k1.local-wrap.AAAAAAAAAAAAAAAA",
                "local-wrap needs wrapping_key.",
            ),
            (
                "k1.secret-wrap.AAAAAAAAAAAAAAAA",
                "Invalid PASERK type: secret-wrap.",
            ),
            (
                "k1.local-pw.AAAAAAAAAAAAAAAA",
                "local-pw needs password.",
            ),
        ],
    )
    def test_vl_local_from_paserk_with_invalid_args(self, paserk, msg):

        with pytest.raises(ValueError) as err:
            V1Local.from_paserk(paserk)
            pytest.fail("Key.from_paserk should fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "paserk, msg",
        [
            ("xx.local-wrap.AAAAAAAAAAAAAAAA", "Invalid PASERK version: xx."),
            ("k1.local-wrap.AAAAAAAAAAAAAAAA", "Invalid PASERK format."),
            ("k1.local-wrap.xxx.AAAAAAAAAAAAAAAA", "Unknown wrapping algorithm: xxx."),
            ("k1.xxx.pie.AAAAAAAAAAAAAAAA", "Invalid PASERK type: xxx."),
        ],
    )
    def test_v1_local_from_paserk_with_wrapping_key_and_invalid_args(self, paserk, msg):

        with pytest.raises(ValueError) as err:
            V1Local.from_paserk(paserk, wrapping_key=token_bytes(32))
            pytest.fail("Key.from_paserk should fail.")
        assert msg in str(err.value)

    def test_v1_local_to_peer_paserk_id(self):
        k = Key.new(1, "local", b"our-secret")
        assert k.to_peer_paserk_id() == ""


class TestV1Public:
    """
    Tests for v1.public.
    """

    def test_v1_public_to_paserk_id(self):
        sk = Key.new(1, "public", load_key("keys/private_key_rsa.pem"))
        pk = Key.new(1, "public", load_key("keys/public_key_rsa.pem"))
        assert sk.to_peer_paserk_id() == pk.to_paserk_id()
        assert pk.to_peer_paserk_id() == ""

    def test_v1_public_verify_via_encode_with_wrong_key(self):
        sk = Key.new(1, "public", load_key("keys/private_key_rsa.pem"))
        pk = Key.new(1, "public", load_key("keys/public_key_rsa_2.pem"))
        token = pyseto.encode(sk, b"Hello world!")
        with pytest.raises(VerifyError) as err:
            pyseto.decode(pk, token)
            pytest.fail("pyseto.decode() should fail.")
        assert "Failed to verify." in str(err.value)

    @pytest.mark.parametrize(
        "paserk, msg",
        [
            ("xx.public.AAAAAAAAAAAAAAAA", "Invalid PASERK version: xx."),
            ("k2.public.AAAAAAAAAAAAAAAA", "Invalid PASERK version: k2."),
            ("k1.public.xxx.AAAAAAAAAAAAAAAA", "Invalid PASERK format."),
            ("k1.local.xxx.AAAAAAAAAAAAAAAA", "Invalid PASERK format."),
            ("k1.xxx.AAAAAAAAAAAAAAAA", "Invalid PASERK type: xxx."),
            ("k1.local.AAAAAAAAAAAAAAAA", "Invalid PASERK type: local."),
            (
                "k1.local-wrap.AAAAAAAAAAAAAAAA",
                "Invalid PASERK type: local-wrap.",
            ),
            (
                "k1.secret-wrap.AAAAAAAAAAAAAAAA",
                "secret-wrap needs wrapping_key.",
            ),
        ],
    )
    def test_vl_public_from_paserk_with_invalid_args(self, paserk, msg):

        with pytest.raises(ValueError) as err:
            V1Public.from_paserk(paserk)
            pytest.fail("Key.from_paserk should fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "paserk, msg",
        [
            ("xx.secret-wrap.pie.AAAAAAAAAAAAAAAA", "Invalid PASERK version: xx."),
            ("k1.secret-wrap.AAAAAAAAAAAAAAAA", "Invalid PASERK format."),
            ("k1.secret-wrap.xxx.AAAAAAAAAAAAAAAA", "Unknown wrapping algorithm: xxx."),
            ("k1.xxx.pie.AAAAAAAAAAAAAAAA", "Invalid PASERK type: xxx."),
        ],
    )
    def test_v1_public_from_paserk_with_wrapping_key_and_invalid_args(self, paserk, msg):

        with pytest.raises(ValueError) as err:
            V1Public.from_paserk(paserk, wrapping_key=token_bytes(32))
            pytest.fail("Key.from_paserk should fail.")
        assert msg in str(err.value)
