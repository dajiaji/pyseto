from secrets import token_bytes

import pytest

from pyseto import NotSupportedError
from pyseto.key_interface import KeyInterface


class TestKeyInterface:
    """
    Tests for KeyInterface.
    """

    @pytest.mark.parametrize(
        "version, purpose, key",
        [
            (1, "local", token_bytes(32)),
            (2, "local", token_bytes(32)),
            (3, "local", token_bytes(32)),
            (4, "local", token_bytes(32)),
        ],
    )
    def test_key_interface_constructor_local(self, version, purpose, key):
        k = KeyInterface(version, purpose, key)
        assert isinstance(k, KeyInterface)
        assert k.version == version
        assert k.purpose == purpose
        assert k.is_secret is True
        with pytest.raises(NotSupportedError) as err:
            k.encrypt(b"Hello world!")
            pytest.fail("KeyInterface.encrypt() should fail.")
        assert "A key for public does not have encrypt()." in str(err.value)
        with pytest.raises(NotSupportedError) as err:
            k.decrypt(b"xxxxxx")
            pytest.fail("KeyInterface.decrypt() should fail.")
        assert "A key for public does not have decrypt()." in str(err.value)
        with pytest.raises(NotSupportedError) as err:
            k.sign(b"Hello world!")
            pytest.fail("KeyInterface.sign() should fail.")
        assert "A key for local does not have sign()." in str(err.value)
        with pytest.raises(NotSupportedError) as err:
            k.verify(b"xxxxxx")
            pytest.fail("KeyInterface.verify() should fail.")
        assert "A key for local does not have verify()." in str(err.value)
        with pytest.raises(NotImplementedError) as err:
            k.to_paserk()
            pytest.fail("KeyInterface.to_paserk() should fail.")
        assert "The PASERK expression for the key is not supported yet." in str(err.value)
        with pytest.raises(NotImplementedError) as err:
            k.to_paserk_id()
            pytest.fail("KeyInterface.to_paserk_id() should fail.")
        assert "The PASERK ID for the key is not supported yet." in str(err.value)
