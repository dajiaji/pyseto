from typing import Union

from .utils import base64url_decode


class Token:
    """
    The parsed PASETO token class.
    """

    def __init__(self, version: str, purpose: str, payload: bytes, footer: bytes = b""):
        self._version = version
        self._purpose = purpose
        self._payload = payload
        self._footer = footer
        self._header = (version + "." + purpose + ".").encode("utf-8")

    @classmethod
    def new(cls, token: Union[bytes, str]):
        token = token if isinstance(token, str) else token.decode("utf-8")
        t = token.split(".")
        if len(t) != 3 and len(t) != 4:
            raise ValueError("token is invalid.")
        p = base64url_decode(t[2])
        f = base64url_decode(t[3]) if len(t) == 4 else b""
        return cls(t[0], t[1], p, f)

    @property
    def version(self) -> str:
        return self._version

    @property
    def purpose(self) -> str:
        return self._purpose

    @property
    def header(self) -> bytes:
        return self._header

    @property
    def payload(self) -> bytes:
        return self._payload

    @payload.setter
    def payload(self, payload: bytes):
        self._payload = payload
        return

    @property
    def footer(self) -> bytes:
        return self._footer

    @footer.setter
    def footer(self, footer: bytes):
        self._footer = footer
        return
