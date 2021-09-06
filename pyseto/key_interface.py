from typing import Any

from .exceptions import NotSupportedError


class KeyInterface:
    """
    The key interface class for PASETO.
    """

    def __init__(self, version: str, type: str, key: Any):
        self._version = version
        self._type = type
        self._header = (self._version + "." + self._type + ".").encode("utf-8")
        self._sig_size = 0
        self._key: Any = key
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
        raise NotSupportedError("A key for public does not have encrypt().")

    def decrypt(
        self, payload: bytes, footer: bytes = b"", implicit_assertion: bytes = b""
    ) -> bytes:
        raise NotSupportedError("A key for public does not have decrypt().")

    def sign(
        self, payload: bytes, footer: bytes = b"", implicit_assertion: bytes = b""
    ) -> bytes:
        raise NotSupportedError("A key for local does not have sign().")

    def verify(
        self, payload: bytes, footer: bytes = b"", implicit_assertion: bytes = b""
    ) -> bytes:
        raise NotSupportedError("A key for local does not have verify().")
