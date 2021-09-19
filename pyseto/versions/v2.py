import hashlib
from secrets import token_bytes
from typing import Any, Union

# from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from Cryptodome.Cipher import ChaCha20, ChaCha20_Poly1305
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..exceptions import DecryptError, EncryptError, SignError, VerifyError
from ..key_interface import KeyInterface
from ..local_key import LocalKey
from ..utils import base64url_decode, base64url_encode, pae


class V2Local(LocalKey):
    """
    The key object for v2.local.
    """

    def __init__(self, key: Union[str, bytes]):

        super().__init__(2, "local", key)
        if len(self._key) != 32:
            raise ValueError("key must be 32 bytes long.")
        return

    @classmethod
    def from_paserk(cls, paserk: str, wrapping_key: bytes = b"") -> KeyInterface:

        frags = paserk.split(".")
        if frags[0] != "k2":
            raise ValueError("Invalid PASERK version for a v2.local key.")
        if frags[1] == "local":
            return cls(base64url_decode(frags[2]))
        if frags[1] == "local-wrap":
            if len(frags) != 4:
                raise ValueError("Invalid PASERK format.")
            if frags[2] != "pie":
                raise ValueError("Unsupported or unknown wrapping algorithm.")
            return cls(cls._decode_pie(wrapping_key, frags[3]))
        raise ValueError("Invalid PASERK type for a v2.local key.")

    def to_paserk(self, wrapping_key: Union[bytes, str] = b"") -> str:

        if not wrapping_key:
            return "k2.local." + base64url_encode(self._key).decode("utf-8")
        bkey = (
            wrapping_key
            if isinstance(wrapping_key, bytes)
            else wrapping_key.encode("utf-8")
        )
        return "k2.local-wrap.pie." + self._encode_pie(bkey, self._key)

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
            raise EncryptError("Failed to encrypt.") from err

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
            raise DecryptError("Failed to decrypt.") from err

    def to_paserk_id(self) -> str:
        h = "k2.lid."
        p = self.to_paserk()
        b = hashlib.blake2b(digest_size=33)
        b.update((h + p).encode("utf-8"))
        d = b.digest()
        return h + base64url_encode(d).decode("utf-8")

    @staticmethod
    def _generate_hash(key: bytes, msg: bytes, size: int) -> bytes:

        try:
            h = hashlib.blake2b(key=key, digest_size=size)
            h.update(msg)
            return h.digest()
        except Exception as err:
            raise EncryptError("Failed to generate hash.") from err

    @staticmethod
    def _generate_nonce(key: bytes, msg: bytes) -> bytes:

        if key:
            if len(key) != 24:
                raise ValueError("nonce must be 24 bytes long.")
        else:
            key = token_bytes(24)

        try:
            h = hashlib.blake2b(key=key, digest_size=24)
            h.update(msg)
            return h.digest()
        except Exception as err:
            raise EncryptError("Failed to generate internal nonce.") from err

    @classmethod
    def _encode_pie(cls, wrapping_key: bytes, ptk: bytes) -> str:
        n = token_bytes(32)
        x = cls._generate_hash(wrapping_key, b"\x80" + n, 56)
        ek = x[0:32]
        n2 = x[32:]
        ak = cls._generate_hash(wrapping_key, b"\x81" + n, 32)
        try:
            cipher = ChaCha20.new(key=ek, nonce=n2)
            c = cipher.encrypt(ptk)
        except Exception as err:
            raise EncryptError("Failed to wrap a key.") from err
        t = cls._generate_hash(ak, b"k2.local-wrap.pie." + n + c, 32)
        return base64url_encode(t + n + c).decode("utf-8")

    @classmethod
    def _decode_pie(cls, wrapping_key: bytes, data: str) -> bytes:
        d = base64url_decode(data)
        t = d[0:32]
        n = d[32:64]
        c = d[64:]
        ak = cls._generate_hash(wrapping_key, b"\x81" + n, 32)
        t2 = cls._generate_hash(ak, b"k2.local-wrap.pie." + n + c, 32)
        if t != t2:
            raise DecryptError("Failed to unwrap a key.")
        x = cls._generate_hash(wrapping_key, b"\x80" + n, 56)
        ek = x[0:32]
        n2 = x[32:]
        try:
            cipher = ChaCha20.new(key=ek, nonce=n2)
            return cipher.decrypt(c)
        except Exception as err:
            raise DecryptError("Failed to unwrap a key.") from err


class V2Public(KeyInterface):
    """
    The key object for v2.public.
    """

    def __init__(self, key: Any):

        super().__init__(2, "public", key)
        self._sig_size = 64

        if not isinstance(self._key, (Ed25519PublicKey, Ed25519PrivateKey)):
            raise ValueError("The key is not Ed25519 key.")
        return

    @classmethod
    def from_paserk(cls, paserk: str, wrapping_key: bytes = b"") -> KeyInterface:
        frags = paserk.split(".")
        if frags[0] != "k2":
            raise ValueError("Invalid PASERK version for a v2.public key.")
        if frags[1] == "public":
            return cls(Ed25519PublicKey.from_public_bytes(base64url_decode(frags[2])))
        elif frags[1] == "secret":
            return cls(
                Ed25519PrivateKey.from_private_bytes(base64url_decode(frags[2])[0:32])
            )
        raise ValueError("Invalid PASERK type for a v2.public key.")

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

    def to_paserk(self, wrapping_key: Union[bytes, str] = b"") -> str:
        if isinstance(self._key, Ed25519PublicKey):
            return (
                "k2.public."
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
        return "k2.secret." + base64url_encode(priv + pub).decode("utf-8")

    def to_paserk_id(self) -> str:
        p = self.to_paserk()
        h = "k2.pid." if isinstance(self._key, Ed25519PublicKey) else "k2.sid."
        b = hashlib.blake2b(digest_size=33)
        b.update((h + p).encode("utf-8"))
        d = b.digest()
        return h + base64url_encode(d).decode("utf-8")
