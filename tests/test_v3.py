from secrets import token_bytes

import pytest

import pyseto
from pyseto import DecryptError, EncryptError, Key, SignError, VerifyError
from pyseto.versions.v3 import V3Local, V3Public

from .utils import load_key


class TestV3Local:
    """
    Tests for v3.local.
    """

    @pytest.mark.parametrize(
        "key, msg",
        [
            (b"", "key must be specified."),
        ],
    )
    def test_v3_local_new_with_invalid_arg(self, key, msg):
        with pytest.raises(ValueError) as err:
            Key.new(3, "local", key)
            pytest.fail("Key.new() should fail.")
        assert msg in str(err.value)

    def test_v3_local_decrypt_via_decode_with_wrong_key(self):
        k1 = Key.new(3, "local", b"our-secret")
        k2 = Key.new(3, "local", b"others-secret")
        token = pyseto.encode(k1, b"Hello world!")
        with pytest.raises(DecryptError) as err:
            pyseto.decode(k2, token)
            pytest.fail("pyseto.decode() should fail.")
        assert "Failed to decrypt." in str(err.value)

    def test_v3_local_encrypt_with_invalid_arg(self):
        k = Key.new(3, "local", b"our-secret")
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
    def test_v3_local_encrypt_via_encode_with_wrong_nonce(self, nonce):
        k = Key.new(3, "local", b"our-secret")
        with pytest.raises(ValueError) as err:
            pyseto.encode(k, b"Hello world!", nonce=nonce)
            pytest.fail("pyseto.encode() should fail.")
        assert "nonce must be 32 bytes long." in str(err.value)

    @pytest.mark.parametrize(
        "paserk, msg",
        [
            ("xx.local.AAAAAAAAAAAAAAAA", "Invalid PASERK version: xx."),
            ("k4.local.AAAAAAAAAAAAAAAA", "Invalid PASERK version: k4."),
            ("k3.local.xxx.AAAAAAAAAAAAAAAA", "Invalid PASERK format."),
            ("k3.public.xxx.AAAAAAAAAAAAAAAA", "Invalid PASERK format."),
            ("k3.xxx.AAAAAAAAAAAAAAAA", "Invalid PASERK type: xxx."),
            ("k3.public.AAAAAAAAAAAAAAAA", "Invalid PASERK type: public."),
            (
                "k3.local-wrap.AAAAAAAAAAAAAAAA",
                "local-wrap needs wrapping_key.",
            ),
            (
                "k3.secret-wrap.AAAAAAAAAAAAAAAA",
                "Invalid PASERK type: secret-wrap.",
            ),
            (
                "k3.local-pw.AAAAAAAAAAAAAAAA",
                "local-pw needs password.",
            ),
        ],
    )
    def test_v3_local_from_paserk_with_invalid_args(self, paserk, msg):

        with pytest.raises(ValueError) as err:
            V3Local.from_paserk(paserk)
            pytest.fail("Key.from_paserk should fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "paserk, msg",
        [
            ("xx.local-wrap.AAAAAAAAAAAAAAAA", "Invalid PASERK version: xx."),
            ("k3.local-wrap.AAAAAAAAAAAAAAAA", "Invalid PASERK format."),
            ("k3.local-wrap.xxx.AAAAAAAAAAAAAAAA", "Unknown wrapping algorithm: xxx."),
            ("k3.xxx.pie.AAAAAAAAAAAAAAAA", "Invalid PASERK type: xxx."),
        ],
    )
    def test_v3_local_from_paserk_with_wrapping_key_and_invalid_args(self, paserk, msg):

        with pytest.raises(ValueError) as err:
            V3Local.from_paserk(paserk, wrapping_key=token_bytes(32))
            pytest.fail("Key.from_paserk should fail.")
        assert msg in str(err.value)

    def test_v3_local_to_peer_paserk_id(self):
        k = Key.new(3, "local", b"our-secret")
        assert k.to_peer_paserk_id() == ""

    # @pytest.mark.parametrize(
    #     "paserk, msg",
    #     [
    #         ("k3.xxx.AAAAAAAAAAAAAAAA", "Invalid PASERK type: xxx."),
    #     ],
    # )
    # def test_v3_local_from_paserk_with_unsealing_key_and_invalid_args(
    #     self, paserk, msg
    # ):

    #     with pytest.raises(ValueError) as err:
    #         V3Local.from_paserk(paserk, unsealing_key=token_bytes(32))
    #         pytest.fail("Key.from_paserk should fail.")
    #     assert msg in str(err.value)

    # def test_v3_local_from_paserk_with_wrong_unsealing_key(self):

    #     k = Key.new(3, "local", token_bytes(32))
    #     with open(get_path("keys/public_key_x25519.pem")) as key_file:
    #         sealed_key = k.to_paserk(sealing_key=key_file.read())

    #     with open(get_path("keys/private_key_x25519_2.pem")) as key_file:
    #         unsealing_key = key_file.read()

    #     with pytest.raises(DecryptError) as err:
    #         Key.from_paserk(sealed_key, unsealing_key=unsealing_key)
    #         pytest.fail("Key.from_paserk should fail.")
    #     assert "Failed to unseal a key." in str(err.value)


class TestV3Public:
    """
    Tests for v3.public.
    """

    def test_v3_public_to_paserk_id(self):
        sk = Key.new(3, "public", load_key("keys/private_key_ecdsa_p384.pem"))
        pk = Key.new(3, "public", load_key("keys/public_key_ecdsa_p384.pem"))
        assert sk.to_peer_paserk_id() == pk.to_paserk_id()
        assert pk.to_peer_paserk_id() == ""

    def test_v3_public_verify_via_encode_with_wrong_key(self):
        sk = Key.new(3, "public", load_key("keys/private_key_ecdsa_p384.pem"))
        pk = Key.new(3, "public", load_key("keys/public_key_ecdsa_p384_2.pem"))
        token = pyseto.encode(sk, b"Hello world!")
        with pytest.raises(VerifyError) as err:
            pyseto.decode(pk, token)
            pytest.fail("pyseto.decode() should fail.")
        assert "Failed to verify." in str(err.value)

    @pytest.mark.parametrize(
        "paserk, msg",
        [
            ("xx.public.AAAAAAAAAAAAAAAA", "Invalid PASERK version: xx."),
            ("k4.public.AAAAAAAAAAAAAAAA", "Invalid PASERK version: k4."),
            ("k3.public.xxx.AAAAAAAAAAAAAAAA", "Invalid PASERK format."),
            ("k3.local.xxx.AAAAAAAAAAAAAAAA", "Invalid PASERK format."),
            ("k3.xxx.AAAAAAAAAAAAAAAA", "Invalid PASERK type: xxx."),
            ("k3.local.AAAAAAAAAAAAAAAA", "Invalid PASERK type: local."),
            (
                "k3.local-wrap.AAAAAAAAAAAAAAAA",
                "Invalid PASERK type: local-wrap.",
            ),
            (
                "k3.secret-wrap.AAAAAAAAAAAAAAAA",
                "secret-wrap needs wrapping_key.",
            ),
        ],
    )
    def test_v3_public_from_paserk_with_invalid_args(self, paserk, msg):

        with pytest.raises(ValueError) as err:
            V3Public.from_paserk(paserk)
            pytest.fail("Key.from_paserk should fail.")
        assert msg in str(err.value)

    @pytest.mark.parametrize(
        "paserk, msg",
        [
            ("xx.secret-wrap.pie.AAAAAAAAAAAAAAAA", "Invalid PASERK version: xx."),
            ("k3.secret-wrap.AAAAAAAAAAAAAAAA", "Invalid PASERK format."),
            ("k3.secret-wrap.xxx.AAAAAAAAAAAAAAAA", "Unknown wrapping algorithm: xxx."),
            ("k3.xxx.pie.AAAAAAAAAAAAAAAA", "Invalid PASERK type: xxx."),
        ],
    )
    def test_v3_public_from_paserk_with_wrapping_key_and_invalid_args(self, paserk, msg):

        with pytest.raises(ValueError) as err:
            V3Public.from_paserk(paserk, wrapping_key=token_bytes(32))
            pytest.fail("Key.from_paserk should fail.")
        assert msg in str(err.value)

    def test_v3_public_from_public_bytes_with_invalid_args(self):

        with pytest.raises(ValueError) as err:
            V3Public.from_public_bytes(b"xxx")
            pytest.fail("Key.from_paserk should fail.")
        assert "Invalid bytes for the key." in str(err.value)

    def test_v3_public_sign_via_encode_with_invalid_key(self):

        k = Key.from_paserk(
            "k3.secret-pw.mXsR2qVqmcDxmSWeQCnCwNeIxe5RDQ3ehnQvdXFj-YgAAAPoFI8eRXCL8PFpVW_CWOvGHnvMPy0BkMlKF1AtmBYGKold9i-ALC2oflkemYdbncrHbiKGd8zfjTQu2tTo2ayOMHybk_-hhopwJ2IUallYfLfUzPuqvtOQfVxXLtUBPnmR75dhRiPDgzdIO1OMbqa3Z1LDevvzbrcPyhHqmJSZioeJ7j1Mu8DJOvrIK0pWHmjDq_eg4YFnaOgz7I3Tkxx89A",
            password="correct horse battery staple".encode("utf-8").hex(),
        )
        with pytest.raises(SignError) as err:
            pyseto.encode(k, b"Hello world!")
            pytest.fail("pyseto.sign() should fail.")
        assert "Failed to sign." in str(err.value)
