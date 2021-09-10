from typing import Any

from .exceptions import NotSupportedError


class KeyInterface:
    """
    The key interface class for PASETO.

    :func:`pyseto.Key.new <pyseto.Key.new>` returns an object which has this interface.
    """

    def __init__(self, version: str, type: str, key: Any):
        self._version = version
        self._type = type
        self._header = (self._version + "." + self._type + ".").encode("utf-8")
        self._sig_size = 0
        self._key: Any = key
        if not self._key:
            raise ValueError("key must be specified.")
        return

    @property
    def version(self) -> str:
        """
        The version of the key. It will be ``"v1"``, ``"v2"``, ``"v3"`` or ``"v4"``.
        """
        return self._version

    @property
    def type(self) -> str:
        """
        The type (purpose) of the key. It will be ``"local"`` or ``"public"``.
        """
        return self._type

    @property
    def header(self) -> bytes:
        """
        The header value for a PASETO token. It will be ``"<version>.<type>."``.
        For example, ``"v1.local."``.
        """
        return self._header

    def encrypt(
        self,
        payload: bytes,
        footer: bytes = b"",
        implicit_assertion: bytes = b"",
        nonce: bytes = b"",
    ) -> bytes:
        """
        Encrypts a message to a PASETO token with the key.

        This function is calld in :func:`pyseto.encode <pyseto.encode>`  so you
        don't need to call it directly.

        Args:
            payload (bytes): A message to be encrypted which will be the payload
                part of the PASETO token.
            footer (bytes): A footer.
            implicit_assertion (Union[bytes, str]): An implicit assertion. It is
                only used in ``v3`` or ``v4``.
            nonce (bytes): A nonce.
        Returns:
            bytes: A PASETO token.
        Raise:
            ValueError: Invalid arguments.
            EncryptError: Failed to encrypt the message.
            NotSupportedError: The key does not support the operation.
        """
        raise NotSupportedError("A key for public does not have encrypt().")

    def decrypt(
        self, payload: bytes, footer: bytes = b"", implicit_assertion: bytes = b""
    ) -> bytes:
        """
        Decrypts an encrypted PASETO token with the key.

        This function is calld in :func:`pyseto.encode <pyseto.decode>`  so you
        don't need to call it directly.

        Args:
            payload (bytes): A message to be decrypted which is the payload part
                of the PASETO token.
            footer (bytes): A footer.
            implicit_assertion (Union[bytes, str]): An implicit assertion. It is
                only used in ``v3`` or ``v4``.
        Returns:
            bytes: A dcrypted payload.
        Raise:
            ValueError: Invalid arguments.
            DecryptError: Failed to decrypt the message.
            NotSupportedError: The key does not support the operation.
        """
        raise NotSupportedError("A key for public does not have decrypt().")

    def sign(
        self, payload: bytes, footer: bytes = b"", implicit_assertion: bytes = b""
    ) -> bytes:
        """
        Signs a message with the key and makes a PASETO token.

        This function is calld in :func:`pyseto.encode <pyseto.encode>`  so you
        don't need to call it directly.

        Args:
            payload (bytes): A message to be signed and encoded which will be
                the payload part of the PASETO token.
            footer (bytes): A footer.
            implicit_assertion (Union[bytes, str]): An implicit assertion. It is
                only used in ``v3`` or ``v4``.
            nonce (bytes): A nonce.
        Returns:
            bytes: A PASETO token.
        Raise:
            ValueError: Invalid arguments.
            EncryptError: Failed to sign the message.
            NotSupportedError: The key does not support the operation.
        """
        raise NotSupportedError("A key for local does not have sign().")

    def verify(
        self, payload: bytes, footer: bytes = b"", implicit_assertion: bytes = b""
    ) -> bytes:
        """
        Verifies and decodes a signed PASETO token with the key.

        This function is calld in :func:`pyseto.encode <pyseto.decode>`  so you
        don't need to call it directly.

        Args:
            payload (bytes): A message to be verified and decoded which is the
                payload part of the PASETO token.
            footer (bytes): A footer.
            implicit_assertion (Union[bytes, str]): An implicit assertion. It is
                only used in ``v3`` or ``v4``.
        Returns:
            bytes: A verified and decoded payload.
        Raise:
            ValueError: Invalid arguments.
            DecryptError: Failed to verify the message.
            NotSupportedError: The key does not support the operation.
        """
        raise NotSupportedError("A key for local does not have verify().")
