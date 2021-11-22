from typing import Union

from .utils import base64url_decode


class Token(object):
    """
    The parsed token object which is a return value of :func:`pyseto.decode <pyseto.decode>`.
    """

    def __init__(
        self,
        version: str,
        purpose: str,
        payload: Union[bytes, dict],
        footer: Union[bytes, dict] = b"",
    ):
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
        if not t[2]:
            raise ValueError("Empty payload.")
        p = base64url_decode(t[2])
        f = base64url_decode(t[3]) if len(t) == 4 else b""
        return cls(t[0], t[1], p, f)

    @property
    def version(self) -> str:
        """
        The version of the token. It will be ``"v1"``, ``"v2"``, ``"v3"`` or ``"v4"``.
        """
        return self._version

    @property
    def purpose(self) -> str:
        """
        The purpose of the token. It will be ``"local"`` or ``"public"``.
        """
        return self._purpose

    @property
    def header(self) -> bytes:
        """
        The header of the token. It will be ``"<version>.<type>."``.
        For example, ``"v1.local."``.
        """
        return self._header

    @property
    def payload(self) -> Union[bytes, dict]:
        """
        The payload of the token which is a decoded binary string. It's not Base64 encoded data.
        """
        return self._payload

    @payload.setter
    def payload(self, payload: Union[bytes, dict]):
        """
        A setter of the payload.
        """
        self._payload = payload
        return

    @property
    def footer(self) -> Union[bytes, dict]:
        """
        The footer of the token which is a decoded binary string. It's not Base64 encoded data.
        """
        return self._footer

    @footer.setter
    def footer(self, footer: Union[bytes, dict]):
        """
        A setter of the footer.
        """
        self._footer = footer
        return
