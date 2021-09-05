from typing import Any, Union

from cryptography import x509
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

from .exceptions import NotSupportedError


class KeyInterface:
    """
    The key interface class for PASETO.
    """

    def __init__(self, version: str, type: str, key: Union[bytes, str]):
        self._version = version
        self._type = type
        self._header = (self._version + "." + self._type + ".").encode("utf-8")
        self._sig_size = 0
        self._key: Any = None

        bkey = key if isinstance(key, bytes) else key.encode("utf-8")
        if self._type == "local":
            self._key = bkey
            return

        skey = key if isinstance(key, str) else key.decode("utf-8")
        if "BEGIN CERTIFICATE" in skey:
            self._key = x509.load_pem_x509_certificate(bkey).public_key()
        elif "BEGIN EC PRIVATE" in skey:
            self._key = load_pem_private_key(bkey, password=None)
        elif "BEGIN PRIVATE" in skey:
            self._key = load_pem_private_key(bkey, password=None)
        elif "BEGIN PUBLIC" in skey:
            self._key = load_pem_public_key(bkey)
        elif "BEGIN RSA PRIVATE" in skey:
            self._key = load_pem_private_key(bkey, password=None)
        else:
            raise ValueError("Failed to decode PEM.")
        return

    @property
    def version(self) -> str:
        return self._version

    @property
    def type(self) -> str:
        return self._type

    @property
    def header(self) -> bytes:
        return self._header

    def encrypt(
        self,
        payload: bytes,
        footer: bytes = b"",
        implicit_assertion: bytes = b"",
        nonce: bytes = b"",
    ) -> bytes:
        raise NotSupportedError()

    def decrypt(
        self, payload: bytes, footer: bytes = b"", implicit_assertion: bytes = b""
    ) -> bytes:
        raise NotSupportedError()

    def sign(
        self, payload: bytes, footer: bytes = b"", implicit_assertion: bytes = b""
    ) -> bytes:
        raise NotSupportedError()

    def verify(
        self, payload: bytes, footer: bytes = b"", implicit_assertion: bytes = b""
    ) -> bytes:
        raise NotSupportedError()
