from .key_interface import KeyInterface
from .utils import base64url_encode


class LocalKey(KeyInterface):
    """
    The local key interface class for PASETO.
    """

    def to_paserk(self) -> str:
        return f"k{self.version}.local." + base64url_encode(self._key).decode("utf-8")
