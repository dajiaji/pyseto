from secrets import token_bytes

import pyseto
from pyseto import Key

from .utils import get_path


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

        private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
        public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"

        private_key = Key.new("v4", "public", private_key_pem)
        token = pyseto.encode(
            private_key,
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

        private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
        public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"

        private_key = Key.new(version=4, type="public", key=private_key_pem)
        token = pyseto.encode(
            private_key,
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

    def test_sample_paserk(self):
        private_key = Key.from_paserk(
            "k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Q"
        )
        token = pyseto.encode(
            private_key,
            b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
        )

        public_key = Key.from_paserk(
            "k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI"
        )
        decoded = pyseto.decode(public_key, token)

        assert (
            private_key.to_paserk()
            == "k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog"
        )
        assert (
            public_key.to_paserk()
            == "k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI"
        )
        assert (
            private_key.to_paserk_id()
            == "k4.sid.9gZFsAQuXhu9lif2pV3rCDjOewsMF4qb4RHGhc0zUklt"
        )
        assert (
            public_key.to_paserk_id()
            == "k4.pid.yh4-bJYjOYAG6CWy0zsfPmpKylxS7uAWrxqVmBN2KAiJ"
        )
        assert (
            decoded.payload
            == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
        )

    def test_sample_rtd_v4_public(self):

        with open(get_path("keys/private_key_ed25519.pem")) as key_file:
            private_key = Key.new(4, "public", key_file.read())
        token = pyseto.encode(
            private_key,
            payload=b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
            footer=b"This is a footer",  # Optional
            implicit_assertion=b"xyz",  # Optional
        )

        with open(get_path("keys/public_key_ed25519.pem")) as key_file:
            public_key = Key.new(4, "public", key_file.read())
        decoded = pyseto.decode(public_key, token, implicit_assertion=b"xyz")

        assert (
            decoded.payload
            == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
        )
        assert decoded.footer == b"This is a footer"
        assert decoded.version == "v4"
        assert decoded.purpose == "public"

    def test_sample_rtd_v4_local(self):

        key = Key.new(version=4, type="local", key=b"our-secret")
        token = pyseto.encode(
            key,
            payload=b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
            footer=b"This is a footer",  # Optional
            implicit_assertion=b"xyz",  # Optional
        )

        decoded = pyseto.decode(key, token, implicit_assertion=b"xyz")

        assert (
            decoded.payload
            == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
        )
        assert decoded.footer == b"This is a footer"
        assert decoded.version == "v4"
        assert decoded.purpose == "local"

    def test_sample_rtd_v3_public(self):

        with open(get_path("keys/private_key_ecdsa_p384.pem")) as key_file:
            private_key = Key.new(3, "public", key_file.read())
        token = pyseto.encode(
            private_key,
            payload=b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
            footer=b"This is a footer",  # Optional
            implicit_assertion=b"xyz",  # Optional
        )

        with open(get_path("keys/public_key_ecdsa_p384.pem")) as key_file:
            public_key = Key.new(3, "public", key_file.read())
        decoded = pyseto.decode(public_key, token, implicit_assertion=b"xyz")

        assert (
            decoded.payload
            == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
        )
        assert decoded.footer == b"This is a footer"
        assert decoded.version == "v3"
        assert decoded.purpose == "public"

    def test_sample_rtd_v3_local(self):

        key = Key.new(version=3, type="local", key=b"our-secret")
        token = pyseto.encode(
            key,
            payload=b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
            footer=b"This is a footer",  # Optional
            implicit_assertion=b"xyz",  # Optional
        )

        decoded = pyseto.decode(key, token, implicit_assertion=b"xyz")

        assert (
            decoded.payload
            == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
        )
        assert decoded.footer == b"This is a footer"
        assert decoded.version == "v3"
        assert decoded.purpose == "local"

    def test_sample_rtd_v2_public(self):

        with open(get_path("keys/private_key_ed25519.pem")) as key_file:
            private_key = Key.new(2, "public", key_file.read())
        token = pyseto.encode(
            private_key,
            payload=b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
            footer=b"This is a footer",  # Optional
        )

        with open(get_path("keys/public_key_ed25519.pem")) as key_file:
            public_key = Key.new(2, "public", key_file.read())
        decoded = pyseto.decode(public_key, token)

        assert (
            decoded.payload
            == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
        )
        assert decoded.footer == b"This is a footer"
        assert decoded.version == "v2"
        assert decoded.purpose == "public"

    def test_sample_rtd_v2_local(self):

        key = Key.new(version=2, type="local", key=token_bytes(32))
        token = pyseto.encode(
            key,
            payload=b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
            footer=b"This is a footer",  # Optional
        )

        decoded = pyseto.decode(key, token)

        assert (
            decoded.payload
            == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
        )
        assert decoded.footer == b"This is a footer"
        assert decoded.version == "v2"
        assert decoded.purpose == "local"

    def test_sample_rtd_v1_public(self):

        with open(get_path("keys/private_key_rsa.pem")) as key_file:
            private_key = Key.new(1, "public", key_file.read())
        token = pyseto.encode(
            private_key,
            payload=b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
            footer=b"This is a footer",  # Optional
        )

        with open(get_path("keys/public_key_rsa.pem")) as key_file:
            public_key = Key.new(1, "public", key_file.read())
        decoded = pyseto.decode(public_key, token)

        assert (
            decoded.payload
            == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
        )
        assert decoded.footer == b"This is a footer"
        assert decoded.version == "v1"
        assert decoded.purpose == "public"

    def test_sample_rtd_v1_local(self):

        key = Key.new(version=1, type="local", key=b"our-secret")
        token = pyseto.encode(
            key,
            payload=b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
            footer=b"This is a footer",  # Optional
        )

        decoded = pyseto.decode(key, token)

        assert (
            decoded.payload
            == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
        )
        assert decoded.footer == b"This is a footer"
        assert decoded.version == "v1"
        assert decoded.purpose == "local"
