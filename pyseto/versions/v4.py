import hashlib
from secrets import token_bytes
from typing import Any, Union

from Cryptodome.Cipher import ChaCha20
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..exceptions import DecryptError, EncryptError, SignError, VerifyError
from ..key_interface import KeyInterface
from ..local_key import LocalKey
from ..utils import base64url_decode, base64url_encode, pae


class V4Local(LocalKey):
    """
    The key object for v4.local.
    """

    def __init__(self, key: Union[str, bytes]):

        super().__init__(4, "local", key)

        if len(self._key) > 64:
            raise ValueError("key length must be up to 64 bytes.")
        return

    @classmethod
    def from_paserk(cls, paserk: str) -> KeyInterface:
        frags = paserk.split(".")
        if frags[0] != "k4":
            raise ValueError("Invalid PASERK version for a v4.local key.")
        if frags[1] != "local":
            raise ValueError("Invalid PASERK type for a v4.local key.")
        return cls(base64url_decode(frags[2]))

    def encrypt(
        self,
        payload: bytes,
        footer: bytes = b"",
        implicit_assertion: bytes = b"",
        nonce: bytes = b"",
    ) -> bytes:

        if nonce:
            if len(nonce) != 32:
                raise ValueError("nonce must be 32 bytes long.")
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
            raise EncryptError("Failed to encrypt.") from err

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
            raise DecryptError("Failed to decrypt.")
        try:
            cipher = ChaCha20.new(key=ek, nonce=n2)
            return cipher.decrypt(c)
        except Exception as err:
            raise DecryptError("Failed to decrypt.") from err

    def to_paserk_id(self) -> str:
        h = "k4.lid."
        p = self.to_paserk()
        b = hashlib.blake2b(digest_size=33)
        b.update((h + p).encode("utf-8"))
        d = b.digest()
        return h + base64url_encode(d).decode("utf-8")

    def _generate_hash(self, key: bytes, msg: bytes, size: int) -> bytes:

        try:
            h = hashlib.blake2b(key=key, digest_size=size)
            h.update(msg)
            return h.digest()
        except Exception as err:
            raise EncryptError("Failed to generate hash.") from err


class V4Public(KeyInterface):
    """
    The key object for v4.public.
    """

    def __init__(self, key: Any):

        super().__init__(4, "public", key)

        self._sig_size = 64

        if not isinstance(self._key, (Ed25519PublicKey, Ed25519PrivateKey)):
            raise ValueError("The key is not Ed25519 key.")
        return

    @classmethod
    def from_paserk(cls, paserk: str) -> KeyInterface:
        frags = paserk.split(".")
        if frags[0] != "k4":
            raise ValueError("Invalid PASERK version for a v4.public key.")
        if frags[1] == "public":
            return cls(Ed25519PublicKey.from_public_bytes(base64url_decode(frags[2])))
        elif frags[1] == "secret":
            return cls(
                Ed25519PrivateKey.from_private_bytes(base64url_decode(frags[2])[0:32])
            )
        raise ValueError("Invalid PASERK type for a v4.public key.")

    # @classmethod
    # def from_public_bytes(cls, key: bytes):
    #     try:
    #         k = Ed25519PublicKey.from_public_bytes(key)
    #     except Exception as err:
    #         raise ValueError("Invalid bytes for the key.") from err
    #     return cls(k)

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

    def to_paserk(self) -> str:
        if isinstance(self._key, Ed25519PublicKey):
            return (
                "k4.public."
                + base64url_encode(
                    self._key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw,
                    )
                ).decode("utf-8")
            )
        priv = self._key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub = self._key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return "k4.secret." + base64url_encode(priv + pub).decode("utf-8")

    def to_paserk_id(self) -> str:
        p = self.to_paserk()
        h = "k4.pid." if isinstance(self._key, Ed25519PublicKey) else "k4.sid."
        b = hashlib.blake2b(digest_size=33)
        b.update((h + p).encode("utf-8"))
        d = b.digest()
        return h + base64url_encode(d).decode("utf-8")
