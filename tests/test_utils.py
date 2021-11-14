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

    def test_utils_i2osp_with_padding(self):
        res = i2osp(
            1773640271034215956220647394962766686220368790999773790300657174885851868252873740857850633982047596450206042428564987609136709554719966122707327315574236228,
            66,
        )
        assert (
            res
            == b"\x00\x84H\xbd\x0e;\xc5\xb7\xdf\\\x1f\xf9\x03\xd2Db\xd1\xdf7\x1b}\x80g4A}\xb0\x19\xcd-\xc6n\x1e&\xe8\xafm\xdd!\xb6\xc3 9}\xb5%\xb3\x02\x87V\xf8\x94C\xe1O\xeb\x14f\x93\xe5\xc7\x8e}#\xa4D"
        )
