import hashlib
from secrets import token_bytes
from typing import Union

from Cryptodome.Cipher import ChaCha20
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..exceptions import DecryptError, EncryptError, SignError, VerifyError
from ..key_interface import KeyInterface
from ..utils import base64url_encode, pae


class V4Local(KeyInterface):
    def __init__(self, key: Union[str, bytes]):
        super().__init__("v4", "local", key)
        return

    def encrypt(
        self,
        payload: bytes,
        footer: bytes = b"",
        implicit_assertion: bytes = b"",
        nonce: bytes = b"",
    ) -> bytes:
        if nonce:
            if len(nonce) != 32:
                raise ValueError("nonce should be 32 bytes.")
        else:
            nonce = token_bytes(32)
        tmp = self._generate_hash(self._key, b"paseto-encryption-key" + nonce, 56)
        ek = tmp[0:32]
        n2 = tmp[32:]
        ak = self._generate_hash(self._key, b"paseto-auth-key-for-aead" + nonce, 32)

        try:
            cipher = ChaCha20.new(key=ek, nonce=n2)
            c = cipher.encrypt(payload)
            pre_auth = pae([self.header, nonce, c, footer, implicit_assertion])
            t = self._generate_hash(ak, pre_auth, 32)
            token = self._header + base64url_encode(nonce + c + t)
            if footer:
                token += b"." + base64url_encode(footer)
            return token
        except Exception as err:
            raise EncryptError("Failed to encrypt a message.") from err

    def decrypt(
        self, payload: bytes, footer: bytes = b"", implicit_assertion: bytes = b""
    ) -> bytes:
        n = payload[0:32]
        c = payload[32 : len(payload) - 32]
        t = payload[-32:]
        tmp = self._generate_hash(self._key, b"paseto-encryption-key" + n, 56)
        ek = tmp[0:32]
        n2 = tmp[32:]
        ak = self._generate_hash(self._key, b"paseto-auth-key-for-aead" + n, 32)
        pre_auth = pae([self.header, n, c, footer, implicit_assertion])
        t2 = self._generate_hash(ak, pre_auth, 32)
        if t != t2:
            raise DecryptError("Hash value mismatch.")
        try:
            cipher = ChaCha20.new(key=ek, nonce=n2)
            return cipher.decrypt(c)
        except Exception as err:
            raise DecryptError("Failed to decrypt a message.") from err

    def _generate_hash(self, key: bytes, msg: bytes, size: int) -> bytes:
        try:
            h = hashlib.blake2b(key=key, digest_size=size)
            h.update(msg)
            return h.digest()
        except Exception as err:
            raise EncryptError("Failed to generate hash.") from err


class V4Public(KeyInterface):
    def __init__(self, key: Union[str, bytes]):
        super().__init__("v4", "public", key)
        self._sig_size = 64

        if not isinstance(self._key, (Ed25519PublicKey, Ed25519PrivateKey)):
            raise ValueError("The key is not Ed25519 key.")
        return

    def sign(
        self, payload: bytes, footer: bytes = b"", implicit_assertion: bytes = b""
    ) -> bytes:
        if isinstance(self._key, Ed25519PublicKey):
            raise ValueError("A public key cannot be used for signing.")
        m2 = pae([self.header, payload, footer, implicit_assertion])
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
        m2 = pae([self.header, m, footer, implicit_assertion])
        try:
            k.verify(sig, m2)
        except Exception as err:
            raise VerifyError("Failed to verify.") from err
        return m
