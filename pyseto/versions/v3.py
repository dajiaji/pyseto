import hashlib
import hmac
from secrets import token_bytes
from typing import Any, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..exceptions import DecryptError, EncryptError, SignError, VerifyError
from ..key_interface import KeyInterface
from ..local_key import LocalKey
from ..utils import base64url_decode, base64url_encode, i2osp, os2ip, pae


class V3Local(LocalKey):
    """
    The key object for v3.local.
    """

    def __init__(self, key: Union[str, bytes]):

        super().__init__(3, "local", key)
        return

    @classmethod
    def from_paserk(cls, paserk: str) -> KeyInterface:
        frags = paserk.split(".")
        if frags[0] != "k3":
            raise ValueError("Invalid PASERK version for a v3.local key.")
        if frags[1] != "local":
            raise ValueError("Invalid PASERK type for a v3.local key.")
        return cls(base64url_decode(frags[2]))

    def encrypt(
        self,
        payload: bytes,
        footer: bytes = b"",
        implicit_assertion: bytes = b"",
        nonce: bytes = b"",
    ) -> bytes:

        if nonce:
            if len(nonce) != 32:
                raise ValueError("nonce must be 32 bytes long.")
        else:
            nonce = token_bytes(32)
        e = HKDF(
            algorithm=hashes.SHA384(),
            length=48,
            salt=None,
            info=b"paseto-encryption-key" + nonce,
        )
        a = HKDF(
            algorithm=hashes.SHA384(),
            length=48,
            salt=None,
            info=b"paseto-auth-key-for-aead" + nonce,
        )
        try:
            tmp = e.derive(self._key)
            ek = tmp[0:32]
            n2 = tmp[32:]
            ak = a.derive(self._key)
        except Exception as err:
            raise DecryptError("Failed to derive keys.") from err

        try:
            c = Cipher(algorithms.AES(ek), modes.CTR(n2)).encryptor().update(payload)
            pre_auth = pae([self.header, nonce, c, footer, implicit_assertion])
            t = hmac.new(ak, pre_auth, hashlib.sha384).digest()
            token = self._header + base64url_encode(nonce + c + t)
            if footer:
                token += b"." + base64url_encode(footer)
            return token
        except Exception as err:
            raise EncryptError("Failed to encrypt.") from err

    def decrypt(
        self, payload: bytes, footer: bytes = b"", implicit_assertion: bytes = b""
    ) -> bytes:

        n = payload[0:32]
        c = payload[32 : len(payload) - 48]
        t = payload[-48:]
        e = HKDF(
            algorithm=hashes.SHA384(),
            length=48,
            salt=None,
            info=b"paseto-encryption-key" + n,
        )
        a = HKDF(
            algorithm=hashes.SHA384(),
            length=48,
            salt=None,
            info=b"paseto-auth-key-for-aead" + n,
        )
        try:
            tmp = e.derive(self._key)
            ek = tmp[0:32]
            n2 = tmp[32:]
            ak = a.derive(self._key)
        except Exception as err:
            raise DecryptError("Failed to derive keys.") from err

        pre_auth = pae([self.header, n, c, footer, implicit_assertion])
        t2 = hmac.new(ak, pre_auth, hashlib.sha384).digest()
        if t != t2:
            raise DecryptError("Failed to decrypt.")

        try:
            return Cipher(algorithms.AES(ek), modes.CTR(n2)).decryptor().update(c)
        except Exception as err:
            raise DecryptError("Failed to decrypt a message.") from err

    def to_paserk_id(self) -> str:
        h = "k3.lid."
        p = self.to_paserk()
        digest = hashes.Hash(hashes.SHA384())
        digest.update((h + p).encode("utf-8"))
        d = digest.finalize()
        return h + base64url_encode(d[0:33]).decode("utf-8")


class V3Public(KeyInterface):
    """
    The key object for v3.public.
    """

    def __init__(self, key: Any):

        super().__init__(3, "public", key)
        self._sig_size = 96

        if not isinstance(self._key, (EllipticCurvePublicKey, EllipticCurvePrivateKey)):
            raise ValueError("The key is not ECDSA key.")
        return

    @classmethod
    def from_paserk(cls, paserk: str) -> KeyInterface:
        frags = paserk.split(".")
        if frags[0] != "k3":
            raise ValueError("Invalid PASERK version for a v3.public key.")
        if frags[1] == "public":
            return cls(
                EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP384R1(), base64url_decode(frags[2])
                )
            )
        # elif frags[1] == "secret":
        #     return cls(Ed25519PrivateKey.from_private_bytes(base64url_decode(frags[2])))
        raise ValueError("Invalid PASERK type for a v3.public key.")

    @classmethod
    def from_public_bytes(cls, key: bytes):
        try:
            k = EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), key)
        except Exception as err:
            raise ValueError("Invalid bytes for the key.") from err
        return cls(k)

    def sign(
        self, payload: bytes, footer: bytes = b"", implicit_assertion: bytes = b""
    ) -> bytes:

        if isinstance(self._key, EllipticCurvePublicKey):
            raise ValueError("A public key cannot be used for signing.")
        pk = self._public_key_compress(
            self._key.private_numbers().public_numbers.x,
            self._key.private_numbers().public_numbers.y,
        )
        m2 = pae([pk, self.header, payload, footer, implicit_assertion])
        try:
            sig = self._key.sign(m2, ec.ECDSA(hashes.SHA384()))
            return self._der_to_os(self._key.curve.key_size, sig)
        except Exception as err:
            raise SignError("Failed to sign.") from err

    def verify(
        self, payload: bytes, footer: bytes = b"", implicit_assertion: bytes = b""
    ):

        if len(payload) <= self._sig_size:
            raise ValueError("Invalid payload.")

        sig = payload[-self._sig_size :]
        m = payload[: len(payload) - self._sig_size]
        k = (
            self._key
            if isinstance(self._key, EllipticCurvePublicKey)
            else self._key.public_key()
        )
        pk = self._public_key_compress(k.public_numbers().x, k.public_numbers().y)
        m2 = pae([pk, self.header, m, footer, implicit_assertion])
        try:
            der_sig = self._os_to_der(self._key.curve.key_size, sig)
            k.verify(der_sig, m2, ec.ECDSA(hashes.SHA384()))
        except Exception as err:
            raise VerifyError("Failed to verify.") from err
        return m

    def to_paserk(self) -> str:
        if isinstance(self._key, EllipticCurvePublicKey):
            data = self._public_key_compress(
                self._key.public_numbers().x, self._key.public_numbers().y
            )
            return "k3.public." + base64url_encode(data).decode("utf-8")
        return (
            "k3.secret."
            + base64url_encode(
                self._key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            ).decode("utf-8")
        )

    def to_paserk_id(self) -> str:
        p = self.to_paserk()
        h = "k3.pid." if isinstance(self._key, EllipticCurvePublicKey) else "k3.sid."
        digest = hashes.Hash(hashes.SHA384())
        digest.update((h + p).encode("utf-8"))
        d = digest.finalize()
        return h + base64url_encode(d[0:33]).decode("utf-8")

    def _public_key_compress(self, x: int, y: int) -> bytes:

        bx = x.to_bytes(48, byteorder="big")
        by = y.to_bytes((y.bit_length() + 7) // 8, byteorder="big")
        s = bytearray(1)
        s[0] = 0x02 + (by[len(by) - 1] & 1)
        return bytes(s) + bx

    def _der_to_os(self, key_size: int, sig: bytes) -> bytes:

        num_bytes = (key_size + 7) // 8
        r, s = decode_dss_signature(sig)
        return i2osp(r, num_bytes) + i2osp(s, num_bytes)

    def _os_to_der(self, key_size: int, sig: bytes) -> bytes:

        num_bytes = (key_size + 7) // 8
        if len(sig) != 2 * num_bytes:
            raise ValueError("Invalid signature.")
        r = os2ip(sig[:num_bytes])
        s = os2ip(sig[num_bytes:])
        return encode_dss_signature(r, s)
