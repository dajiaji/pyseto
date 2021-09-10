from typing import List, Union

from .key_interface import KeyInterface
from .token import Token
from .utils import base64url_encode


def encode(
    key: KeyInterface,
    payload: Union[bytes, str],
    footer: Union[bytes, str] = b"",
    implicit_assertion: Union[bytes, str] = b"",
    nonce: bytes = b"",
) -> bytes:
    """
    Encodes a message to a PASETO token with a key for encryption or signing.

    Args:
        key (KeyInterface): A key for encryption or signing.
        payload (Union[bytes, str]): A message to be encrypted or signed.
        footer (Union[bytes, str]): A footer.
        implicit_assertion (Union[bytes, str]): An implicit assertion. It is
            only used in ``v3`` or ``v4``.
        nonce (bytes): A nonce. If omitted(it's recommended), a nonce will be
            generated with ``secrets.token_bytes()`` internally. If you don't
            want ot use ``secrets.token_bytes()``, you can specify it via this
            parameter explicitly.
    Returns:
        bytes: A PASETO token.
    Raise:
        ValueError: Invalid arguments.
        EncryptError: Failed to encrypt the message.
        SignError: Failed to sign the message.
    """
    bp = payload if isinstance(payload, bytes) else payload.encode("utf-8")
    bf = footer if isinstance(footer, bytes) else footer.encode("utf-8")
    bi = (
        implicit_assertion
        if isinstance(implicit_assertion, bytes)
        else implicit_assertion.encode("utf-8")
    )
    if key.type == "local":
        return key.encrypt(bp, bf, bi, nonce)

    sig = key.sign(bp, bf, bi)
    token = key.header + base64url_encode(bp + sig)
    if bf:
        token += b"." + base64url_encode(bf)
    return token


def decode(
    keys: Union[KeyInterface, List[KeyInterface]],
    token: Union[bytes, str],
    implicit_assertion: Union[bytes, str] = b"",
) -> Token:
    """
    Decodes a PASETO token with a key for decryption and/or verifying.

    Args:
        key (KeyInterface): A key for decryption or verifying the signature in the token.
        token (Union[bytes, str]): A PASETO token to be decrypted or verified.
        implicit_assertion (Union[bytes, str]): An implicit assertion. It is
            only used in ``v3`` or ``v4``.
    Returns:
        Token: A parsed PASETO token object.
    Raise:
        ValueError: Invalid arguments.
        DecryptError: Failed to decrypt the message.
        VerifyError: Failed to verify the message.
    """
    keys = keys if isinstance(keys, list) else [keys]
    bi = (
        implicit_assertion
        if isinstance(implicit_assertion, bytes)
        else implicit_assertion.encode("utf-8")
    )

    failed = None
    t = Token.new(token)
    for k in keys:
        if k.header != t.header:
            continue
        try:
            if k.type == "local":
                t.payload = k.decrypt(t.payload, t.footer, bi)
                return t
            t.payload = k.verify(t.payload, t.footer, bi)
            return t
        except Exception as err:
            failed = err
    if failed:
        raise failed
    raise ValueError("key is not found for verifying the token.")
