import pytest

from pyseto.utils import i2osp


class TestUtils:
    """
    Tests for utils.
    """

    def test_utils_i2osp_invalid_arg(self):
        with pytest.raises(ValueError) as err:
            i2osp(270, 1)
            pytest.fail("i2osp should fail.")
        assert "integer too large" in str(err.value)
