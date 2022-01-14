import json
import time
from datetime import datetime, timedelta, timezone
from secrets import token_bytes

import freezegun
import iso8601

import pyseto
from pyseto import Key, Paseto

from .utils import get_path


class TestSample:
    """
    Tests for sample code.
    """

    def test_sample_v4_local_old(self):

        key = Key.new(4, "local", b"our-secret")
        token = pyseto.encode(
            key,
            b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
        )

        decoded = pyseto.decode(key, token)
        assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'

    def test_sample_v4_public_old(self):

        private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
        public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"

        private_key = Key.new(4, "public", private_key_pem)
        token = pyseto.encode(
            private_key,
            b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
        )
        public_key = Key.new(4, "public", public_key_pem)
        decoded = pyseto.decode(public_key, token)

        assert (
            token
            == b"v4.public.eyJkYXRhIjogInRoaXMgaXMgYSBzaWduZWQgbWVzc2FnZSIsICJleHAiOiAiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9l1YiKei2FESvHBSGPkn70eFO1hv3tXH0jph1IfZyEfgm3t1DjkYqD5r4aHWZm1eZs_3_bZ9pBQlZGp0DPSdzDg"
        )
        assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'

    def test_sample_v4_local(self):

        key = Key.new(version=4, purpose="local", key=b"our-secret")
        token = pyseto.encode(
            key,
            b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
        )

        decoded = pyseto.decode(key, token)
        assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'

    def test_sample_v4_public(self):

        private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
        public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"

        private_key = Key.new(version=4, purpose="public", key=private_key_pem)
        token = pyseto.encode(
            private_key,
            b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
        )
        public_key = Key.new(version=4, purpose="public", key=public_key_pem)
        decoded = pyseto.decode(public_key, token)

        assert (
            token
            == b"v4.public.eyJkYXRhIjogInRoaXMgaXMgYSBzaWduZWQgbWVzc2FnZSIsICJleHAiOiAiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9l1YiKei2FESvHBSGPkn70eFO1hv3tXH0jph1IfZyEfgm3t1DjkYqD5r4aHWZm1eZs_3_bZ9pBQlZGp0DPSdzDg"
        )
        assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'

    @freezegun.freeze_time("2021-01-01")
    def test_sample_v4_public_with_serializer(self):

        private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
        public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"

        private_key = Key.new(version=4, purpose="public", key=private_key_pem)
        token = pyseto.encode(
            private_key,
            {"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"},
        )
        public_key = Key.new(version=4, purpose="public", key=public_key_pem)
        decoded = pyseto.decode(public_key, token, deserializer=json)

        assert (
            token
            == b"v4.public.eyJkYXRhIjogInRoaXMgaXMgYSBzaWduZWQgbWVzc2FnZSIsICJleHAiOiAiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9l1YiKei2FESvHBSGPkn70eFO1hv3tXH0jph1IfZyEfgm3t1DjkYqD5r4aHWZm1eZs_3_bZ9pBQlZGp0DPSdzDg"
        )
        assert decoded.payload["data"] == "this is a signed message"
        assert decoded.payload["exp"] == "2022-01-01T00:00:00+00:00"

    def test_sample_v4_local_with_serializer(self):

        key = Key.new(version=4, purpose="local", key=b"out-secret")
        token = pyseto.encode(
            key,
            {"data": "this is a signed message"},
        )
        decoded = pyseto.decode(key, token, deserializer=json)
        assert decoded.payload["data"] == "this is a signed message"

    def test_sample_v4_public_with_serializer_and_exp(self):

        private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
        public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"
        now = datetime.now(tz=timezone.utc)

        private_key = Key.new(version=4, purpose="public", key=private_key_pem)
        token = pyseto.encode(
            private_key,
            {"data": "this is a signed message"},
            exp=3600,
        )
        public_key = Key.new(version=4, purpose="public", key=public_key_pem)
        decoded = pyseto.decode(public_key, token, deserializer=json)

        assert decoded.payload["data"] == "this is a signed message"
        assert iso8601.parse_date(decoded.payload["exp"]) >= now + timedelta(seconds=3600 - 1)

    def test_sample_v4_public_with_paseto_class(self):

        private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
        public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"
        now = datetime.now(tz=timezone.utc)

        private_key = Key.new(version=4, purpose="public", key=private_key_pem)
        paseto = Paseto.new(exp=3600, include_iat=True)
        token = paseto.encode(
            private_key,
            {"data": "this is a signed message"},
        )
        public_key = Key.new(version=4, purpose="public", key=public_key_pem)
        decoded = pyseto.decode(public_key, token, deserializer=json)

        assert decoded.payload["data"] == "this is a signed message"
        assert "iat" in decoded.payload
        assert "exp" in decoded.payload
        assert iso8601.parse_date(decoded.payload["exp"]) >= now + timedelta(seconds=3600 - 1)

    def test_sample_v4_public_with_paseto_class_and_leeway(self):

        private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
        public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"
        now = datetime.now(tz=timezone.utc)

        private_key = Key.new(version=4, purpose="public", key=private_key_pem)
        paseto = Paseto.new(exp=1, include_iat=True, leeway=1)
        token = paseto.encode(
            private_key,
            {"data": "this is a signed message"},
        )
        time.sleep(1)
        public_key = Key.new(version=4, purpose="public", key=public_key_pem)
        decoded = pyseto.decode(public_key, token, deserializer=json)

        assert decoded.payload["data"] == "this is a signed message"
        assert "iat" in decoded.payload
        assert "exp" in decoded.payload
        assert iso8601.parse_date(decoded.payload["exp"]) >= now

    def test_sample_v4_public_with_kid(self):

        private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
        public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"
        now = datetime.now(tz=timezone.utc)

        private_key = Key.new(version=4, purpose="public", key=private_key_pem)
        public_key = Key.new(version=4, purpose="public", key=public_key_pem)
        paseto = Paseto.new(exp=3600, include_iat=True)
        token = paseto.encode(
            private_key,
            {
                "data": "this is a signed message",
                "nbf": (now - timedelta(seconds=10)).isoformat(timespec="seconds"),
            },
            footer={"kid": public_key.to_paserk_id()},
        )
        decoded = pyseto.decode(public_key, token, deserializer=json)

        assert decoded.payload["data"] == "this is a signed message"
        assert "iat" in decoded.payload
        assert "exp" in decoded.payload
        assert "kid" in decoded.footer
        assert decoded.footer["kid"] == "k4.pid.yh4-bJYjOYAG6CWy0zsfPmpKylxS7uAWrxqVmBN2KAiJ"
        assert iso8601.parse_date(decoded.payload["exp"]) >= now

    def test_sample_paserk(self):

        symmetric_key = Key.new(version=4, purpose="local", key=b"our-secret")
        private_key = Key.from_paserk(
            "k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog"
        )
        public_key = Key.from_paserk("k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI")

        token = pyseto.encode(
            private_key,
            b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
        )
        decoded = pyseto.decode(public_key, token)
        assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'

        assert symmetric_key.to_paserk() == "k4.local.b3VyLXNlY3JldA"
        assert (
            private_key.to_paserk()
            == "k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog"
        )
        assert public_key.to_paserk() == "k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI"

    def test_sample_paserk_id(self):

        symmetric_key = Key.new(version=4, purpose="local", key=b"our-secret")
        private_key = Key.from_paserk(
            "k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog"
        )
        public_key = Key.from_paserk("k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI")

        assert symmetric_key.to_paserk_id() == "k4.lid._D6kgTzxgiPGk35gMj9bukgj4En2H94u22wVX9zaoh05"
        assert private_key.to_paserk_id() == "k4.sid.9gZFsAQuXhu9lif2pV3rCDjOewsMF4qb4RHGhc0zUklt"
        assert public_key.to_paserk_id() == "k4.pid.yh4-bJYjOYAG6CWy0zsfPmpKylxS7uAWrxqVmBN2KAiJ"

    def test_sample_paserk_key_wrapping_local(self):

        raw_key = Key.new(version=4, purpose="local", key=b"our-secret")
        wrapping_key = token_bytes(32)
        wpk = raw_key.to_paserk(wrapping_key=wrapping_key)

        # assert wpk == "k4.local-wrap.pie.TNKEwC4K1xBcgJ_GiwWAoRlQFE33HJO3oN9DHEZ05pieSCd-W7bgAL64VG9TZ_pBkuNBFHNrfOGHtnfnhYGdbz5-x3CxShhPJxg"

        unwrapped_key = Key.from_paserk(wpk, wrapping_key=wrapping_key)
        token = pyseto.encode(
            raw_key,
            b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
        )
        decoded = pyseto.decode(unwrapped_key, token)
        assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'

    def test_sample_paserk_key_wrapping_public(self):

        raw_private_key = Key.from_paserk(
            "k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog"
        )
        public_key = Key.from_paserk("k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI")
        wrapping_key = token_bytes(32)
        wpk = raw_private_key.to_paserk(wrapping_key=wrapping_key)

        # assert wpk == "k4.secret-wrap.pie.excv7V4-NaECy5hpji-tkSkMvyjsAgNxA-mGALgdjyvGNyDlTb89bJ35R1e3tILgbMpEW5WXMXzySe2T-sBz-ZAcs1j7rbD3ZWvsBTM6K5N9wWfAxbR4ppCXH_H5__9yY-kBaF2NimyAJyduhOhSmqLm6TTSucpAOakEJOXePW8"

        unwrapped_private_key = Key.from_paserk(wpk, wrapping_key=wrapping_key)
        token = pyseto.encode(
            unwrapped_private_key,
            b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
        )
        decoded = pyseto.decode(public_key, token)
        assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'

    def test_sample_paserk_password_local(self):

        raw_key = Key.new(version=4, purpose="local", key=b"our-secret")
        wpk = raw_key.to_paserk(password="our-secret")

        # assert wpk == "k4.local-pw.HrCs9Pu-2LB0l7jkHB-x2gAAAAAA8AAAAAAAAgAAAAGttW0IHZjQCHJdg-Vc3tqO_GSLR4vzLl-yrKk2I-l8YHj6jWpC0lQB2Z7uzTtVyV1rd_EZQPzHdw5VOtyucP0FkCU"

        unwrapped_key = Key.from_paserk(wpk, password="our-secret")
        token = pyseto.encode(
            raw_key,
            b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
        )
        decoded = pyseto.decode(unwrapped_key, token)
        assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'

    def test_sample_paserk_password_public(self):

        raw_private_key = Key.from_paserk(
            "k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog"
        )
        public_key = Key.from_paserk("k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI")
        wpk = raw_private_key.to_paserk(password="our-secret")

        # assert wpk == "k4.secret-pw.MEMW4K1MaD5nWigCLyEyFAAAAAAA8AAAAAAAAgAAAAFU-tArtryNVjS2n2hCYiM11V6tOyuIog69Bjb0yNZanrLJ3afGclb3kPzQ6IhK8ob9E4QgRdEALGWCizZ0RCPFF_M95IQDfmdYKC0Er656UgKUK4UKG9JlxP4o81UwoJoZYz_D1zTlltipEa5RiNvUtNU8vLKoGSY"

        unwrapped_private_key = Key.from_paserk(wpk, password="our-secret")
        token = pyseto.encode(
            unwrapped_private_key,
            b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
        )
        decoded = pyseto.decode(public_key, token)
        assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'

    def test_sample_paserk_seal(self):

        raw_key = Key.new(version=4, purpose="local", key=b"our-secret")
        token = pyseto.encode(
            raw_key,
            b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
        )
        with open(get_path("keys/public_key_x25519.pem")) as key_file:
            sealed_key = raw_key.to_paserk(sealing_key=key_file.read())

        with open(get_path("keys/private_key_x25519.pem")) as key_file:
            unsealed_key = Key.from_paserk(sealed_key, unsealing_key=key_file.read())
        decoded = pyseto.decode(unsealed_key, token)
        assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'

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

        assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
        assert decoded.footer == b"This is a footer"
        assert decoded.version == "v4"
        assert decoded.purpose == "public"

    def test_sample_rtd_v4_local(self):

        key = Key.new(version=4, purpose="local", key=b"our-secret")
        token = pyseto.encode(
            key,
            payload=b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
            footer=b"This is a footer",  # Optional
            implicit_assertion=b"xyz",  # Optional
        )

        decoded = pyseto.decode(key, token, implicit_assertion=b"xyz")

        assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
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

        assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
        assert decoded.footer == b"This is a footer"
        assert decoded.version == "v3"
        assert decoded.purpose == "public"

    def test_sample_rtd_v3_local(self):

        key = Key.new(version=3, purpose="local", key=b"our-secret")
        token = pyseto.encode(
            key,
            payload=b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
            footer=b"This is a footer",  # Optional
            implicit_assertion=b"xyz",  # Optional
        )

        decoded = pyseto.decode(key, token, implicit_assertion=b"xyz")

        assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
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

        assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
        assert decoded.footer == b"This is a footer"
        assert decoded.version == "v2"
        assert decoded.purpose == "public"

    def test_sample_rtd_v2_local(self):

        key = Key.new(version=2, purpose="local", key=token_bytes(32))
        token = pyseto.encode(
            key,
            payload=b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
            footer=b"This is a footer",  # Optional
        )

        decoded = pyseto.decode(key, token)

        assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
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

        assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
        assert decoded.footer == b"This is a footer"
        assert decoded.version == "v1"
        assert decoded.purpose == "public"

    def test_sample_rtd_v1_local(self):

        key = Key.new(version=1, purpose="local", key=b"our-secret")
        token = pyseto.encode(
            key,
            payload=b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
            footer=b"This is a footer",  # Optional
        )

        decoded = pyseto.decode(key, token)

        assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
        assert decoded.footer == b"This is a footer"
        assert decoded.version == "v1"
        assert decoded.purpose == "local"
