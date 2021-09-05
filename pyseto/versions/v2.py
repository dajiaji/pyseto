import hashlib
from secrets import token_bytes
from typing import Union

# from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from Cryptodome.Cipher import ChaCha20_Poly1305
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..exceptions import DecryptError, EncryptError, SignError, VerifyError
from ..key_interface import KeyInterface
from ..utils import base64url_encode, pae


class V2Local(KeyInterface):
    def __init__(self, key: Union[str, bytes]):
        super().__init__("v2", "local", key)
        return

    def encrypt(
        self,
        payload: bytes,
        footer: bytes = b"",
        implicit_assertion: bytes = b"",
        nonce: bytes = b"",
    ) -> bytes:
        n = self._generate_nonce(nonce, payload)
        pre_auth = pae([self.header, n, footer])

        try:
            cipher = ChaCha20_Poly1305.new(key=self._key, nonce=n)
            cipher.update(pre_auth)
            c, tag = cipher.encrypt_and_digest(payload)
            token = self._header + base64url_encode(n + c + tag)
            if footer:
                token += b"." + base64url_encode(footer)
            return token
        except Exception as err:
            raise EncryptError("Failed to encrypt a message.") from err

    def decrypt(
        self, payload: bytes, footer: bytes = b"", implicit_assertion: bytes = b""
    ) -> bytes:
        n = payload[0:24]
        c = payload[24 : len(payload) - 16]
        tag = payload[-16:]
        pre_auth = pae([self.header, n, footer])

        try:
            cipher = ChaCha20_Poly1305.new(key=self._key, nonce=n)
            cipher.update(pre_auth)
            return cipher.decrypt_and_verify(c, tag)
        except Exception as err:
            raise DecryptError("Failed to decrypt a message.") from err

    def _generate_nonce(self, key: bytes, msg: bytes) -> bytes:
        if key:
            if len(key) != 24:
                raise ValueError("nonce should be 24 bytes.")
        else:
            key = token_bytes(24)

        try:
            h = hashlib.blake2b(key=key, digest_size=24)
            h.update(msg)
            return h.digest()
        except Exception as err:
            raise EncryptError("Failed to get nonce.") from err


class V2Public(KeyInterface):
    def __init__(self, key: Union[str, bytes]):
        super().__init__("v2", "public", key)
        self._sig_size = 64

        if not isinstance(self._key, (Ed25519PublicKey, Ed25519PrivateKey)):
            raise ValueError("The key is not Ed25519 key.")
        return

    def sign(
        self, payload: bytes, footer: bytes = b"", implicit_assertion: bytes = b""
    ) -> bytes:
        if isinstance(self._key, Ed25519PublicKey):
            raise ValueError("A public key cannot be used for signing.")
        m2 = pae([self.header, payload, footer])
        try:
            return self._key.sign(m2)
        except Exception as err:
            raise SignError("Failed to sign.") from err

    def verify(
        self, payload: bytes, footer: bytes = b"", implicit_assertion: bytes = b""
    ):
        if len(payload) <= self._sig_size:
            raise ValueError("Invalid payload.")

        sig = payload[-self._sig_size :]
        m = payload[: len(payload) - self._sig_size]
        k = (
            self._key
            if isinstance(self._key, Ed25519PublicKey)
            else self._key.public_key()
        )
        m2 = pae([self.header, m, footer])
        try:
            k.verify(sig, m2)
        except Exception as err:
            raise VerifyError("Failed to verify.") from err
        return m
