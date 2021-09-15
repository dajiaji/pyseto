from .key_interface import KeyInterface
from .utils import base64url_encode


class LocalKey(KeyInterface):
    """
    The local key interface class for PASETO.
    """

    def to_paserk(self) -> str:
        """
        Returns the PASERK expression of the key.

        Returns:
            str: A PASERK string.
        """
        return f"k{self.version}.local." + base64url_encode(self._key).decode("utf-8")
