import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

import pyseto
from pyseto import Key
from pyseto.versions.v3 import V3Public

from .utils import get_path


def _load_tests(paths: list) -> list:

    tests: list = []
    for path in paths:
        with open(get_path(path)) as tv_file:
            tv = json.loads(tv_file.read())
        tests += tv["tests"]
    return tests


def _name_to_version(name: str) -> int:

    v = name.split(".")[0]
    if len(v) != 2:
        raise ValueError("Invalid PASERK test name.")
    return int(v[1:])


def _public_key_compress(x: int, y: int) -> bytes:

    bx = x.to_bytes(48, byteorder="big")
    by = y.to_bytes((y.bit_length() + 7) // 8, byteorder="big")
    s = bytearray(1)
    s[0] = 0x02 + (by[len(by) - 1] & 1)
    return bytes(s) + bx


def _from_Ed25519PrivateKey_to_X25519PrivateKey(data: bytes) -> X25519PrivateKey:

    hasher = hashes.Hash(hashes.SHA512())
    hasher.update(data)
    h = bytearray(hasher.finalize())

    # curve25519 clamping
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return bytes(h[0:32])


class TestWithTestVectors:
    """
    Tests with test vectors defined in https://github.com/paseto-standard/test-vectors.
    """

    @pytest.mark.parametrize(
        "v",
        _load_tests(
            [
                "vectors/v1.json",
                "vectors/v2.json",
                "vectors/v3.json",
                "vectors/v4.json",
            ]
        ),
    )
    def test_with_test_vectors(self, v):

        token = v["token"].encode("utf-8")
        payload = v["payload"]
        footer = v["footer"].encode("utf-8")
        implicit_assertion = v["implicit-assertion"].encode("utf-8")

        version = int(v["name"].split("-")[0])
        purpose = v["name"].split("-")[1]

        if v["expect-fail"]:
            if "public-key" not in v:
                nonce = bytes.fromhex(v["nonce"])
                key = bytes.fromhex(v["key"])

                k = Key.new(version, "local", key=key)
                with pytest.raises(ValueError) as err:
                    pyseto.encode(k, payload, footer, implicit_assertion, nonce=nonce)
                    pytest.fail("encode should fail.")
                assert "payload should be bytes, str or dict." in str(err.value)
                return

            secret_key_pem = v["secret-key"] if version == 1 else v["secret-key-pem"]
            public_key_pem = v["public-key"] if version == 1 else v["public-key-pem"]

            sk = Key.new(version, "public", secret_key_pem)
            with pytest.raises(ValueError) as err:
                pyseto.encode(sk, payload, footer, implicit_assertion)
                pytest.fail("encode should fail.")
            assert "payload should be bytes, str or dict." in str(err.value)
            return

        payload = payload.encode("utf-8")
        if purpose == "E":
            nonce = bytes.fromhex(v["nonce"])
            key = bytes.fromhex(v["key"])

            k = Key.new(version, "local", key=key)
            encoded = pyseto.encode(k, payload, footer, implicit_assertion, nonce=nonce)
            decoded_token = pyseto.decode(k, token, implicit_assertion)
            decoded = pyseto.decode(k, encoded, implicit_assertion)
            assert payload == decoded_token.payload == decoded.payload
            return

        if purpose == "S":
            secret_key_pem = v["secret-key"] if version == 1 else v["secret-key-pem"]
            public_key_pem = v["public-key"] if version == 1 else v["public-key-pem"]

            sk = Key.new(version, "public", secret_key_pem)
            encoded = pyseto.encode(sk, payload, footer, implicit_assertion)
            pk = Key.new(version, "public", public_key_pem)
            decoded_token = pyseto.decode(pk, token, implicit_assertion)
            decoded = pyseto.decode(pk, encoded, implicit_assertion)
            assert payload == decoded_token.payload == decoded.payload

            if version == 1:
                return

            secret_key = bytes.fromhex(v["secret-key"])
            public_key = bytes.fromhex(v["public-key"])

            if version == 3:
                # TODO add support for secret-key/public-key on v3.public test vectors.
                return

            sk = Key.from_asymmetric_key_params(version, d=secret_key[0:32])
            encoded = pyseto.encode(sk, payload, footer, implicit_assertion)
            pk = Key.from_asymmetric_key_params(version, x=public_key)
            decoded_token = pyseto.decode(pk, token, implicit_assertion)
            decoded = pyseto.decode(pk, encoded, implicit_assertion)
            assert payload == decoded_token.payload == decoded.payload
            return
        pytest.fail(f"Invalid test name: {v['name']}")

    @pytest.mark.parametrize(
        "v",
        _load_tests(
            [
                "vectors/PASERK/k1.public.json",
                "vectors/PASERK/k2.public.json",
                "vectors/PASERK/k3.public.json",
                "vectors/PASERK/k4.public.json",
            ]
        ),
    )
    def test_with_test_vectors_paserk_public(self, v):

        version = _name_to_version(v["name"])
        if version == 1:
            k = Key.new(version, "public", v["key"])
        elif version == 2 or version == 4:
            k = Key.from_asymmetric_key_params(version, x=bytes.fromhex(v["key"]))
        elif version == 3:
            k = V3Public.from_public_bytes(bytes.fromhex(v["key"]))
        else:
            pytest.fail("Unsupported version.")
        assert k.to_paserk() == v["paserk"]
        k2 = Key.from_paserk(v["paserk"])
        assert k2.to_paserk() == v["paserk"]

    @pytest.mark.parametrize(
        "v",
        _load_tests(
            [
                "vectors/PASERK/k1.secret.json",
                "vectors/PASERK/k2.secret.json",
                "vectors/PASERK/k3.secret.json",
                "vectors/PASERK/k4.secret.json",
            ]
        ),
    )
    def test_with_test_vectors_paserk_secret(self, v):

        version = _name_to_version(v["name"])
        if version == 1:
            k = Key.new(version, "public", v["key"])
        elif version == 2 or version == 4:
            k = Key.from_asymmetric_key_params(version, d=bytes.fromhex(v["secret-key-seed"]))
        elif version == 3:
            pub_k = Key.new(version, "public", bytes.fromhex(v["public-key"]))
            bx = pub_k._key.public_numbers().x.to_bytes(48, byteorder="big")
            by = pub_k._key.public_numbers().y.to_bytes(48, byteorder="big")
            k = Key.from_asymmetric_key_params(version, x=bx, y=by, d=bytes.fromhex(v["key"]))
        else:
            pytest.fail("Unsupported version.")
        assert k.to_paserk() == v["paserk"]
        k2 = Key.from_paserk(v["paserk"])
        assert k2.to_paserk() == v["paserk"]

    @pytest.mark.parametrize(
        "v",
        _load_tests(
            [
                "vectors/PASERK/k1.local.json",
                "vectors/PASERK/k2.local.json",
                "vectors/PASERK/k3.local.json",
                "vectors/PASERK/k4.local.json",
            ]
        ),
    )
    def test_with_test_vectors_paserk_local(self, v):

        version = _name_to_version(v["name"])
        k = Key.new(version, "local", bytes.fromhex(v["key"]))
        k2 = Key.from_paserk(v["paserk"])
        assert k.to_paserk() == v["paserk"]
        assert k2.to_paserk() == v["paserk"]

    @pytest.mark.parametrize(
        "v",
        _load_tests(
            [
                "vectors/PASERK/k1.pid.json",
                "vectors/PASERK/k2.pid.json",
                "vectors/PASERK/k3.pid.json",
                "vectors/PASERK/k4.pid.json",
            ]
        ),
    )
    def test_with_test_vectors_paserk_pid(self, v):

        version = _name_to_version(v["name"])
        if version == 1:
            k = Key.new(version, "public", v["key"])
        elif version == 2 or version == 4:
            k = Key.from_asymmetric_key_params(version, x=bytes.fromhex(v["key"]))
        elif version == 3:
            k = V3Public.from_public_bytes(bytes.fromhex(v["key"]))
        else:
            pytest.fail("Unsupported version.")
        assert k.to_paserk_id() == v["paserk"]

    @pytest.mark.parametrize(
        "v",
        _load_tests(
            [
                "vectors/PASERK/k1.sid.json",
                "vectors/PASERK/k2.sid.json",
                "vectors/PASERK/k3.sid.json",
                "vectors/PASERK/k4.sid.json",
            ]
        ),
    )
    def test_with_test_vectors_paserk_sid(self, v):

        version = _name_to_version(v["name"])
        if version == 1:
            k = Key.new(version, "public", v["key"])
        elif version == 2 or version == 4:
            k = Key.from_asymmetric_key_params(version, d=bytes.fromhex(v["seed"]))
        elif version == 3:
            pub_k = Key.new(version, "public", bytes.fromhex(v["public-key"]))
            bx = pub_k._key.public_numbers().x.to_bytes(48, byteorder="big")
            by = pub_k._key.public_numbers().y.to_bytes(48, byteorder="big")
            k = Key.from_asymmetric_key_params(version, x=bx, y=by, d=bytes.fromhex(v["key"]))
        else:
            pytest.fail("Unsupported version.")
        assert k.to_paserk_id() == v["paserk"]

    @pytest.mark.parametrize(
        "v",
        _load_tests(
            [
                "vectors/PASERK/k1.lid.json",
                "vectors/PASERK/k2.lid.json",
                "vectors/PASERK/k3.lid.json",
                "vectors/PASERK/k4.lid.json",
            ]
        ),
    )
    def test_with_test_vectors_paserk_lid(self, v):

        version = _name_to_version(v["name"])
        k = Key.new(version, "local", bytes.fromhex(v["key"]))
        assert k.to_paserk_id() == v["paserk"]

    @pytest.mark.parametrize(
        "v",
        _load_tests(
            [
                "vectors/PASERK/k1.local-wrap.pie.json",
                "vectors/PASERK/k2.local-wrap.pie.json",
                "vectors/PASERK/k3.local-wrap.pie.json",
                "vectors/PASERK/k4.local-wrap.pie.json",
            ]
        ),
    )
    def test_with_test_vectors_paserk_local_wrap_pie(self, v):

        version = _name_to_version(v["name"])
        k = Key.from_paserk(v["paserk"], wrapping_key=bytes.fromhex(v["wrapping-key"]))

        k1 = Key.new(version, "local", bytes.fromhex(v["unwrapped"]))
        wpk = k1.to_paserk(wrapping_key=bytes.fromhex(v["wrapping-key"]))
        k2 = Key.from_paserk(wpk, wrapping_key=bytes.fromhex(v["wrapping-key"]))

        t = pyseto.encode(k, b"Hello world!")
        d = pyseto.decode(k, t)
        d1 = pyseto.decode(k1, t)
        d2 = pyseto.decode(k2, t)
        assert d.payload == d1.payload == d2.payload == b"Hello world!"

        t = pyseto.encode(k1, b"Hello world!")
        d1 = pyseto.decode(k1, t)
        d2 = pyseto.decode(k2, t)
        assert d1.payload == d2.payload == b"Hello world!"

        d = pyseto.decode(k, t)
        assert d.payload == b"Hello world!"

    @pytest.mark.parametrize(
        "v",
        _load_tests(
            [
                "vectors/PASERK/k1.secret-wrap.pie.json",
                "vectors/PASERK/k2.secret-wrap.pie.json",
                "vectors/PASERK/k3.secret-wrap.pie.json",
                "vectors/PASERK/k4.secret-wrap.pie.json",
            ]
        ),
    )
    def test_with_test_vectors_paserk_secret_wrap_pie(self, v):

        version = _name_to_version(v["name"])

        k = Key.from_paserk(v["paserk"], wrapping_key=bytes.fromhex(v["wrapping-key"]))

        if version == 1:
            k1 = Key.new(version, "public", v["unwrapped"])
        elif version == 2 or version == 4:
            k1 = Key.from_asymmetric_key_params(version, d=bytes.fromhex(v["unwrapped"])[0:32])
        elif version == 3:
            pub_k = Key.new(version, "public", bytes.fromhex(v["public-key"]))
            bx = pub_k._key.public_numbers().x.to_bytes(48, byteorder="big")
            by = pub_k._key.public_numbers().y.to_bytes(48, byteorder="big")
            k1 = Key.from_asymmetric_key_params(version, x=bx, y=by, d=bytes.fromhex(v["unwrapped"]))
        else:
            pytest.fail("Unsupported version.")

        wpk = k1.to_paserk(wrapping_key=bytes.fromhex(v["wrapping-key"]))
        k2 = Key.from_paserk(wpk, wrapping_key=bytes.fromhex(v["wrapping-key"]))

        t = pyseto.encode(k, b"Hello world!")
        d = pyseto.decode(k, t)
        d1 = pyseto.decode(k1, t)
        d2 = pyseto.decode(k2, t)
        assert d.payload == d1.payload == d2.payload == b"Hello world!"

        t = pyseto.encode(k1, b"Hello world!")
        d1 = pyseto.decode(k1, t)
        d2 = pyseto.decode(k2, t)
        assert d1.payload == d2.payload == b"Hello world!"

        d = pyseto.decode(k, t)
        assert d.payload == b"Hello world!"

    @pytest.mark.parametrize(
        "v",
        _load_tests(
            [
                "vectors/PASERK/k1.local-pw.json",
                "vectors/PASERK/k2.local-pw.json",
                "vectors/PASERK/k3.local-pw.json",
                "vectors/PASERK/k4.local-pw.json",
            ]
        ),
    )
    def test_with_test_vectors_paserk_local_pw(self, v):

        version = _name_to_version(v["name"])

        k = Key.from_paserk(v["paserk"], password=v["password"])

        k1 = Key.new(version, "local", bytes.fromhex(v["unwrapped"]))
        if version in [1, 3]:
            wpk = k1.to_paserk(password=v["password"], iteration=v["options"]["iterations"])
        elif version in [2, 4]:
            wpk = k1.to_paserk(
                password=v["password"],
                memory_cost=int(v["options"]["memlimit"] / 1024),
                time_cost=v["options"]["opslimit"],
            )
        else:
            pytest.fail("Unsupported version.")

        k2 = Key.from_paserk(wpk, password=v["password"])
        assert k1._key == k2._key

        t = pyseto.encode(k, b"Hello world!")
        d = pyseto.decode(k, t)
        d1 = pyseto.decode(k1, t)
        d2 = pyseto.decode(k2, t)
        assert d.payload == d1.payload == d2.payload == b"Hello world!"

        t = pyseto.encode(k1, b"Hello world!")
        d1 = pyseto.decode(k1, t)
        d2 = pyseto.decode(k2, t)
        assert d1.payload == d2.payload == b"Hello world!"

        d = pyseto.decode(k, t)
        assert d.payload == b"Hello world!"
        version = _name_to_version(v["name"])

    @pytest.mark.parametrize(
        "v",
        _load_tests(
            [
                "vectors/PASERK/k1.secret-pw.json",
                "vectors/PASERK/k2.secret-pw.json",
                "vectors/PASERK/k3.secret-pw.json",
                "vectors/PASERK/k4.secret-pw.json",
            ]
        ),
    )
    def test_with_test_vectors_paserk_secret_pw(self, v):

        version = _name_to_version(v["name"])

        k = Key.from_paserk(v["paserk"], password=v["password"])

        if version == 1:
            k1 = Key.new(version, "public", v["unwrapped"])
        elif version == 2 or version == 4:
            k1 = Key.from_asymmetric_key_params(version, d=bytes.fromhex(v["unwrapped"])[0:32])
        elif version == 3:
            pub_k = Key.new(version, "public", bytes.fromhex(v["public-key"]))
            bx = pub_k._key.public_numbers().x.to_bytes(48, byteorder="big")
            by = pub_k._key.public_numbers().y.to_bytes(48, byteorder="big")
            k1 = Key.from_asymmetric_key_params(version, x=bx, y=by, d=bytes.fromhex(v["unwrapped"]))
        else:
            pytest.fail("Unsupported version.")

        if version in [1, 3]:
            wpk = k1.to_paserk(password=v["password"], iteration=v["options"]["iterations"])
        elif version in [2, 4]:
            wpk = k1.to_paserk(
                password=v["password"],
                memory_cost=int(v["options"]["memlimit"] / 1024),
                time_cost=v["options"]["opslimit"],
            )
        else:
            pytest.fail("Unsupported version.")

        k2 = Key.from_paserk(wpk, password=v["password"])

        t = pyseto.encode(k, b"Hello world!")
        d = pyseto.decode(k, t)
        d1 = pyseto.decode(k1, t)
        d2 = pyseto.decode(k2, t)
        assert d.payload == d1.payload == d2.payload == b"Hello world!"

        t = pyseto.encode(k1, b"Hello world!")
        d1 = pyseto.decode(k1, t)
        d2 = pyseto.decode(k2, t)
        assert d1.payload == d2.payload == b"Hello world!"

        d = pyseto.decode(k, t)
        assert d.payload == b"Hello world!"

    @pytest.mark.parametrize(
        "v",
        _load_tests(
            [
                "vectors/PASERK/k2.seal.json",
                "vectors/PASERK/k4.seal.json",
            ]
        ),
    )
    def test_with_test_vectors_paserk_seal_v2_v4(self, v):

        version = _name_to_version(v["name"])

        if version == 1:
            raise NotImplementedError("Not implemented.")
        elif version in [2, 4]:
            sk_ed25519 = bytes.fromhex(v["sealing-secret-key"])[0:32]
            tmp_key = _from_Ed25519PrivateKey_to_X25519PrivateKey(sk_ed25519)
            sk_x25519 = X25519PrivateKey.from_private_bytes(tmp_key)
            unsealing_key = sk_x25519.private_bytes(
                Encoding.PEM,
                PrivateFormat.PKCS8,
                NoEncryption(),
            )
            sealing_key = sk_x25519.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        elif version == 3:
            sk = load_pem_private_key(v["sealing-secret-key"].encode("utf-8"), password=None)
            unsealing_key = sk.private_numbers().private_value.to_bytes(48, byteorder="big")
            sealing_key = _public_key_compress(
                sk.private_numbers().public_numbers.x,
                sk.private_numbers().public_numbers.y,
            )
        else:
            pytest.fail("Unsupported version.")

        k = Key.from_paserk(v["paserk"], unsealing_key=unsealing_key)
        k1 = Key.new(version, "local", bytes.fromhex(v["unsealed"]))
        wpk = k1.to_paserk(sealing_key=sealing_key)

        k2 = Key.from_paserk(wpk, unsealing_key=unsealing_key)
        assert k1._key == k2._key

        t = pyseto.encode(k, b"Hello world!")
        d = pyseto.decode(k, t)
        d1 = pyseto.decode(k1, t)
        d2 = pyseto.decode(k2, t)
        assert d.payload == d1.payload == d2.payload == b"Hello world!"

        t = pyseto.encode(k1, b"Hello world!")
        d1 = pyseto.decode(k1, t)
        d2 = pyseto.decode(k2, t)
        assert d1.payload == d2.payload == b"Hello world!"

        d = pyseto.decode(k, t)
        assert d.payload == b"Hello world!"

    # @pytest.mark.parametrize(
    #     "v",
    #     _load_tests(
    #         [
    #             # "vectors/PASERK/k1.seal.json",
    #             "vectors/PASERK/k3.seal.json",
    #         ]
    #     ),
    # )
    # def test_with_test_vectors_paserk_seal_v1_v3(self, v):

    #     version = _name_to_version(v["name"])

    #     if version == 1:
    #         raise NotImplementedError("Not implemented.")
    #     elif version == 3:
    #         sk = load_pem_private_key(
    #             v["sealing-secret-key"].encode("utf-8"), password=None
    #         )
    #         unsealing_key = sk.private_numbers().private_value.to_bytes(
    #             48, byteorder="big"
    #         )
    #         sealing_key = _public_key_compress(
    #             sk.private_numbers().public_numbers.x,
    #             sk.private_numbers().public_numbers.y,
    #         )
    #     else:
    #         pytest.fail("Unsupported version.")

    #     # k = Key.from_paserk(v["paserk"], unsealing_key=unsealing_key)
    #     k1 = Key.new(version, "local", bytes.fromhex(v["unsealed"]))
    #     wpk = k1.to_paserk(sealing_key=sealing_key)

    #     k2 = Key.from_paserk(wpk, unsealing_key=unsealing_key)
    #     assert k1._key == k2._key

    #     # t = pyseto.encode(k, b"Hello world!")
    #     # d = pyseto.decode(k, t)
    #     # d1 = pyseto.decode(k1, t)
    #     # d2 = pyseto.decode(k2, t)
    #     # assert d.payload == d1.payload == d2.payload == b"Hello world!"

    #     t = pyseto.encode(k1, b"Hello world!")
    #     d1 = pyseto.decode(k1, t)
    #     d2 = pyseto.decode(k2, t)
    #     assert d1.payload == d2.payload == b"Hello world!"

    #     # d = pyseto.decode(k, t)
    #     # assert d.payload == b"Hello world!"
