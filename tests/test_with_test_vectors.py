import json

import pytest

import pyseto
from pyseto import Key

from .utils import get_path


def _load_tests(paths: list) -> list:
    tests: list = []
    for path in paths:
        with open(get_path(path)) as tv_file:
            tv = json.loads(tv_file.read())
        tests += tv["tests"]
    return tests


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
        payload = json.dumps(v["payload"], separators=(",", ":")).encode("utf-8")
        footer = v["footer"].encode("utf-8")
        implicit_assertion = v["implicit-assertion"].encode("utf-8")

        version = v["name"].split("-")[0]
        purpose = v["name"].split("-")[1]
        if purpose == "E":
            nonce = bytes.fromhex(v["nonce"])
            key = bytes.fromhex(v["key"])

            k = Key.new("v" + version, "local", key=key)
            encoded = pyseto.encode(k, payload, footer, implicit_assertion, nonce=nonce)
            decoded_token = pyseto.decode(k, token, implicit_assertion)
            decoded = pyseto.decode(k, encoded, implicit_assertion)
            assert payload == decoded_token.payload == decoded.payload
            return

        if purpose == "S":
            secret_key_pem = v["secret-key"] if version == "1" else v["secret-key-pem"]
            public_key_pem = v["public-key"] if version == "1" else v["public-key-pem"]

            sk = Key.new("v" + version, "public", secret_key_pem)
            encoded = pyseto.encode(sk, payload, footer, implicit_assertion)
            pk = Key.new("v" + version, "public", public_key_pem)
            decoded_token = pyseto.decode(pk, token, implicit_assertion)
            decoded = pyseto.decode(pk, encoded, implicit_assertion)
            assert payload == decoded_token.payload == decoded.payload

            if version == "1":
                return

            secret_key = bytes.fromhex(v["secret-key"])
            public_key = bytes.fromhex(v["public-key"])

            if version == "3":
                # TODO add support for secret-key/public-key on v3.public test vectors.
                return

            sk = Key.from_asymmetric_key_params("v" + version, d=secret_key[0:32])
            encoded = pyseto.encode(sk, payload, footer, implicit_assertion)
            pk = Key.from_asymmetric_key_params("v" + version, x=public_key)
            decoded_token = pyseto.decode(pk, token, implicit_assertion)
            decoded = pyseto.decode(pk, encoded, implicit_assertion)
            assert payload == decoded_token.payload == decoded.payload
            return
        pytest.fail(f"Invalid test name: {v['name']}")
