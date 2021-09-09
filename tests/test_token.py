import pytest

from pyseto.token import Token
from pyseto.utils import base64url_decode


class TestToken:
    """
    Tests for Token.
    """

    def test_token_new(self):
        token = Token.new(
            b"v1.local.WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8"
        )
        assert token.version == "v1"
        assert token.purpose == "local"
        assert token.payload == base64url_decode(
            "WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8"
        )
        assert token.footer == b""

    def test_token_new_with_str(self):
        token = Token.new(
            "v1.local.WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8"
        )
        assert token.version == "v1"
        assert token.purpose == "local"
        assert token.payload == base64url_decode(
            "WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8"
        )
        assert token.footer == b""

    def test_token_setter_payload(self):
        token = Token.new(
            b"v1.local.WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8"
        )
        token.payload = b"updated-payload"
        assert token.payload == b"updated-payload"

    def test_token_setter_footer(self):
        token = Token.new(
            b"v1.local.WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8"
        )
        token.footer = b"updated-footer"
        assert token.footer == b"updated-footer"

    @pytest.mark.parametrize(
        "token, msg",
        [
            ("v1", "token is invalid."),
            ("v1.", "token is invalid."),
            ("v1.local", "token is invalid."),
            ("v1.local.", "Empty payload."),
            ("v1.local.p.f.x", "token is invalid."),
            ("v1.local.p.f.x.y", "token is invalid."),
        ],
    )
    def test_token_new_with_invalid_token(self, token, msg):
        with pytest.raises(ValueError) as err:
            Token.new(token)
            pytest.fail("Token.new() should fail.")
        assert msg in str(err.value)
