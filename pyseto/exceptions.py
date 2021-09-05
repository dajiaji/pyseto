class PysetoError(Exception):
    """
    Base class for all exceptions.
    """

    pass


class NotSupportedError(PysetoError):
    """
    An Exception occurred when the function is not supported for the key object.
    """

    pass


class EncryptError(PysetoError):
    """
    An Exception occurred when an encryption process failed.
    """

    pass


class DecryptError(PysetoError):
    """
    An Exception occurred when an decryption process failed.
    """

    pass


class SignError(PysetoError):
    """
    An Exception occurred when a signing process failed.
    """

    pass


class VerifyError(PysetoError):
    """
    An Exception occurred when a verification process failed.
    """

    pass
