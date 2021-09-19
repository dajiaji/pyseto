import hashlib
from secrets import token_bytes
from typing import Union

# from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from Cryptodome.Cipher import ChaCha20

from .exceptions import DecryptError, EncryptError
from .key_interface import KeyInterface
from .utils import base64url_decode, base64url_encode


class SodiumKey(KeyInterface):
    """
    Sodium (v2, v4) PASETO key.
    """

    # _VERSION = 2 or 4
    # _TYPE = "local", "public" or "secret"

    def __init__(self, key: Union[str, bytes]):

        super().__init__(self._VERSION, self._TYPE, key)
        return

    @classmethod
    def from_paserk(cls, paserk: str, wrapping_key: bytes = b"") -> KeyInterface:

        frags = paserk.split(".")
        if frags[0] != f"k{cls._VERSION}":
            raise ValueError(f"Invalid PASERK version for a v{cls._VERSION}.local key.")
        if frags[1] == "local":
            return cls(base64url_decode(frags[2]))
        if frags[1] == "local-wrap":
            if len(frags) != 4:
                raise ValueError("Invalid PASERK format.")
            if frags[2] != "pie":
                raise ValueError("Unsupported or unknown wrapping algorithm.")
            header = frags[0] + "." + frags[1] + ".pie."
            return cls(cls._decode_pie(header, wrapping_key, frags[3]))
        raise ValueError(f"Invalid PASERK type for a v{cls._VERSION}.local key.")

    def to_paserk(self, wrapping_key: Union[bytes, str] = b"") -> str:

        if not wrapping_key:
            h = f"k{self.version}.local."
            return h + base64url_encode(self._key).decode("utf-8")
        bkey = (
            wrapping_key
            if isinstance(wrapping_key, bytes)
            else wrapping_key.encode("utf-8")
        )
        h = f"k{self.version}.local-wrap.pie."
        return h + self._encode_pie(h, bkey, self._key)

    @classmethod
    def _encode_pie(cls, header: str, wrapping_key: bytes, ptk: bytes) -> str:

        h = header.encode("utf-8")
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
        t = cls._generate_hash(ak, h + n + c, 32)
        return base64url_encode(t + n + c).decode("utf-8")

    @classmethod
    def _decode_pie(cls, header: str, wrapping_key: bytes, data: str) -> bytes:

        h = header.encode("utf-8")
        d = base64url_decode(data)
        t = d[0:32]
        n = d[32:64]
        c = d[64:]
        ak = cls._generate_hash(wrapping_key, b"\x81" + n, 32)
        t2 = cls._generate_hash(ak, h + n + c, 32)
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

    @staticmethod
    def _generate_hash(key: bytes, msg: bytes, size: int) -> bytes:

        try:
            h = hashlib.blake2b(key=key, digest_size=size)
            h.update(msg)
            return h.digest()
        except Exception as err:
            raise EncryptError("Failed to generate hash.") from err
