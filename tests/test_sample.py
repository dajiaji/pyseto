import pyseto
from pyseto import Key


class TestSample:
    """
    Tests for sample code.
    """

    def test_sample_v4_local_old(self):

        key = Key.new("v4", "local", b"our-secret")
        token = pyseto.encode(
            key,
            b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
        )

        decoded = pyseto.decode(key, token)
        assert (
            decoded.payload
            == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
        )

    def test_sample_v4_public_old(self):
        secret_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
        public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"

        secret_key = Key.new("v4", "public", secret_key_pem)
        token = pyseto.encode(
            secret_key,
            b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
        )
        public_key = Key.new("v4", "public", public_key_pem)
        decoded = pyseto.decode(public_key, token)

        assert (
            token
            == b"v4.public.eyJkYXRhIjogInRoaXMgaXMgYSBzaWduZWQgbWVzc2FnZSIsICJleHAiOiAiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9l1YiKei2FESvHBSGPkn70eFO1hv3tXH0jph1IfZyEfgm3t1DjkYqD5r4aHWZm1eZs_3_bZ9pBQlZGp0DPSdzDg"
        )
        assert (
            decoded.payload
            == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
        )

    def test_sample_v4_local(self):

        key = Key.new(version=4, type="local", key=b"our-secret")
        token = pyseto.encode(
            key,
            b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
        )

        decoded = pyseto.decode(key, token)
        assert (
            decoded.payload
            == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
        )

    def test_sample_v4_public(self):
        secret_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
        public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"

        secret_key = Key.new(version=4, type="public", key=secret_key_pem)
        token = pyseto.encode(
            secret_key,
            b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
        )
        public_key = Key.new(version=4, type="public", key=public_key_pem)
        decoded = pyseto.decode(public_key, token)

        assert (
            token
            == b"v4.public.eyJkYXRhIjogInRoaXMgaXMgYSBzaWduZWQgbWVzc2FnZSIsICJleHAiOiAiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9l1YiKei2FESvHBSGPkn70eFO1hv3tXH0jph1IfZyEfgm3t1DjkYqD5r4aHWZm1eZs_3_bZ9pBQlZGp0DPSdzDg"
        )
        assert (
            decoded.payload
            == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
        )
