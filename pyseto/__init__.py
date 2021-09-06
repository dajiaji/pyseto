from .exceptions import (
    DecryptError,
    EncryptError,
    NotSupportedError,
    PysetoError,
    SignError,
    VerifyError,
)
from .key import Key
from .pyseto import decode, encode

__version__ = "0.3.2"
__title__ = "PySETO"
__description__ = "A Python implementation of PASETO"
__url__ = "https://pyseto.readthedocs.io"
__uri__ = __url__
__doc__ = __description__ + " <" + __uri__ + ">"
__author__ = "AJITOMI Daisuke"
__email__ = "ajitomi@gmail.com"
__license__ = "MIT"
__copyright__ = "Copyright 2021 AJITOMI Daisuke"
__all__ = [
    "encode",
    "decode",
    "Key",
    "PysetoError",
    "DecryptError",
    "EncryptError",
    "NotSupportedError",
    "SignError",
    "VerifyError",
]
