import json
from typing import Any, List, Optional, Union

from .key_interface import KeyInterface
from .token import Token
from .utils import base64url_encode


def encode(
    key: KeyInterface,
    payload: Union[bytes, str, dict],
    footer: Union[bytes, str] = b"",
    implicit_assertion: Union[bytes, str] = b"",
    nonce: bytes = b"",
    serializer: Any = json,
) -> bytes:

    """
    Encodes a message to a PASETO token with a key for encryption or signing.

    Args:
        key (KeyInterface): A key for encryption or signing.
        payload (Union[bytes, str, dict]): A message to be encrypted or signed.
        footer (Union[bytes, str]): A footer.
        implicit_assertion (Union[bytes, str]): An implicit assertion. It is
            only used in ``v3`` or ``v4``.
        nonce (bytes): A nonce. If omitted(it's recommended), a nonce will be
            generated with ``secrets.token_bytes()`` internally. If you don't
            want ot use ``secrets.token_bytes()``, you can specify it via this
            parameter explicitly.
        serializer (Any): A serializer which is used when the type of
            ``payload`` is ``object``. It must have a ``dumps()`` function to
            serialize the payload. Typically, you can use ``json`` or ``cbor2``.
    Returns:
        bytes: A PASETO token.
    Raise:
        ValueError: Invalid arguments.
        EncryptError: Failed to encrypt the message.
        SignError: Failed to sign the message.
    """
    if not isinstance(payload, (bytes, str, dict)):
        raise ValueError("payload should be bytes, str or dict.")

    bp: bytes
    if isinstance(payload, dict):
        if not serializer:
            raise ValueError("serializer should be specified for the payload object.")
        try:
            if not callable(serializer.dumps):
                raise ValueError("serializer should have dumps().")
        except AttributeError:
            raise ValueError("serializer should have dumps().")
        except Exception:
            raise
        try:
            bp = serializer.dumps(payload).encode("utf-8")
        except Exception as err:
            raise ValueError("Failed to serialize the payload.") from err
    else:
        bp = payload if isinstance(payload, bytes) else payload.encode("utf-8")

    bf = footer if isinstance(footer, bytes) else footer.encode("utf-8")
    bi = (
        implicit_assertion
        if isinstance(implicit_assertion, bytes)
        else implicit_assertion.encode("utf-8")
    )
    if key.purpose == "local":
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
    deserializer: Optional[Any] = None,
) -> Token:

    """
    Decodes a PASETO token with a key for decryption and/or verifying.

    Args:
        key (KeyInterface): A key for decryption or verifying the signature in the token.
        token (Union[bytes, str]): A PASETO token to be decrypted or verified.
        implicit_assertion (Union[bytes, str]): An implicit assertion. It is
            only used in ``v3`` or ``v4``.
        deserializer (Optional[Any]): A deserializer which is used when you want to
            deserialize a ``payload`` attribute in the response object. It must have a
            ``loads()`` function to deserialize the payload. Typically, you can use
            ``json`` or ``cbor2``.
    Returns:
        Token: A parsed PASETO token object.
    Raise:
        ValueError: Invalid arguments.
        DecryptError: Failed to decrypt the message.
        VerifyError: Failed to verify the message.
    """
    if deserializer:
        try:
            if not callable(deserializer.loads):
                raise ValueError("deserializer should have loads().")
        except AttributeError:
            raise ValueError("deserializer should have loads().")
        except Exception:
            raise

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
            if k.purpose == "local":
                t.payload = k.decrypt(t.payload, t.footer, bi)
                return t
            t.payload = k.verify(t.payload, t.footer, bi)
            try:
                if deserializer:
                    t.payload = deserializer.loads(t.payload)
            except Exception as err:
                raise ValueError("Failed to deserialize the payload.") from err
            return t
        except Exception as err:
            failed = err
    if failed:
        raise failed
    raise ValueError("key is not found for verifying the token.")
