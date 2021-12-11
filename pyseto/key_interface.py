from typing import Any, Union

from .exceptions import NotSupportedError


class KeyInterface:
    """
    The key interface class for PASETO.

    :func:`pyseto.Key.new <pyseto.Key.new>` returns an object which has this interface.
    """

    _VERSION = 0
    _TYPE = ""

    def __init__(self, version: int, purpose: str, key: Any):
        self._version = version
        self._purpose = purpose
        self._header = (f"v{self._version}." + self._purpose + ".").encode("utf-8")
        self._sig_size = 0
        self._key: Any = key
        if not self._key:
            raise ValueError("key must be specified.")
        self._is_secret = True
        return

    @property
    def version(self) -> int:
        """
        The version of the key. It will be ``1``, ``2``, ``3`` or ``4``.
        """
        return self._version

    @property
    def purpose(self) -> str:
        """
        The purpose of the key. It will be ``"local"`` or ``"public"``.
        """
        return self._purpose

    @property
    def header(self) -> bytes:
        """
        The header value for a PASETO token. It will be ``"v<version>.<purpose>."``.
        For example, ``"v1.local."``.
        """
        return self._header

    @property
    def is_secret(self) -> bool:
        """
        If it is True, the key is a symmetric key or an asymmetric secret key.
        """
        return self._is_secret

    # @property
    # def key(self) -> Any:
    #     """
    #     Byte string or pyca/cryptography key object of the key.
    #     If the key is ``public``, the key object is one of the pyca/cryptography objects bellow:

    #     - ``RSAPrivateKey``
    #     - ``RSAPublicKey``
    #     - ``Ed25519PrivateKey``
    #     - ``Ed25519PublicKey``
    #     - ``EllipticCurvePrivateKey``
    #     - ``EllipticCurvePublicKey``
    #     """
    #     return self._key

    def to_paserk(
        self,
        wrapping_key: Union[bytes, str] = b"",
        password: Union[bytes, str] = b"",
        sealing_key: Union[bytes, str] = b"",
        iteration: int = 100000,
        memory_cost: int = 15 * 1024,
        time_cost: int = 2,
        parallelism: int = 1,
    ) -> str:
        """
        Returns the PASERK expression of the key.

        Args:
            wrapping_key (Union[bytes, str]): A wrapping key to wrap the key.
                If the `wrapping_key` is specified, `password` should not be
                specified.
            password (Union[bytes, str]): A password to wrap the key. If the
                `password` is specified, `wrapping_key` should not be specified.
            iteration (int): An iteration count used for password-based key
                wrapping. This argument will only be used when the `password` is
                specified.
            memory_cost (int): Amount of memory to use for password-based key
                wrapping using argon2. This argument will only be used when
                the `password` is specified for `v2/v4` key.
            time_cost (int):  Number of iterations to perform for password-based
                key wrapping using argon2. This argument will only be used when
                the `password` is specified for `v2/v4` key.
            parallelism (int): Degree of parallelism for password-based key
                wrapping using argon2. This argument will only be used when
                the `password` is specified for `v2/v4` key.
        Returns:
            str: A PASERK string.
        Raise:
            ValueError: Invalid arguments.
            EncryptError: Failed to wrap the key.
        """
        raise NotImplementedError("The PASERK expression for the key is not supported yet.")

    def to_paserk_id(self) -> str:
        """
        Returns the PASERK ID of the key.

        Returns:
            str: A PASERK ID string.
        """
        raise NotImplementedError("The PASERK ID for the key is not supported yet.")

    def to_peer_paserk_id(self) -> str:
        """
        Returns the peer(public) PASERK ID of the key.
        It can be used only in case that the key is `k2.secret` or `k4.secret`.

        Returns:
            str: A peer PASERK ID string. If the key is neither `k2.secret` nor
                `k4.secret`, an empty string will be returned.
        """
        return ""

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

    def decrypt(self, payload: bytes, footer: bytes = b"", implicit_assertion: bytes = b"") -> bytes:
        """
        Decrypts an encrypted PASETO token with the key.

        This function is calld in :func:`pyseto.decode <pyseto.decode>`  so you
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

    def sign(self, payload: bytes, footer: bytes = b"", implicit_assertion: bytes = b"") -> bytes:
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

    def verify(self, payload: bytes, footer: bytes = b"", implicit_assertion: bytes = b"") -> bytes:
        """
        Verifies and decodes a signed PASETO token with the key.

        This function is calld in :func:`pyseto.decode <pyseto.decode>`  so you
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
