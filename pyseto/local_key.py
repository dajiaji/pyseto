from typing import Any

from .key_interface import KeyInterface
from .utils import base64url_encode


class LocalKey(KeyInterface):
    """
    The local key interface class for PASETO.
    """

    def __init__(self, version: int, type: str, key: Any):

        super().__init__(version, type, key)
        return

    def to_paserk(self) -> str:
        return f"k{self.version}.local." + base64url_encode(self._key).decode("utf-8")
