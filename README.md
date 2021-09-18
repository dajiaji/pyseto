# PySETO - A Python implementation of PASETO

[![PyPI version](https://badge.fury.io/py/pyseto.svg)](https://badge.fury.io/py/pyseto)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pyseto)
[![Documentation Status](https://readthedocs.org/projects/pyseto/badge/?version=latest)](https://pyseto.readthedocs.io/en/latest/?badge=latest)
![Github CI](https://github.com/dajiaji/pyseto/actions/workflows/python-package.yml/badge.svg)
[![codecov](https://codecov.io/gh/dajiaji/pyseto/branch/main/graph/badge.svg?token=QN8GXEYEP3)](https://codecov.io/gh/dajiaji/pyseto)


PySETO is a [PASETO (Platform-Agnostic SEcurity TOkens)](https://paseto.io/) implementation written in Python which supports all of the versions and purposes below.

- [Version 1: NIST Compatibility](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version1.md)
    - ✅ Local: Symmetric Authenticated Encryption
        - AES-256-CTR + HMAC-SHA384 (Encrypt-then-MAC).
    - ✅ Public: Asymmetric Authentication (Public-Key Signatures)
        - RSASSA-PSS with 2048-bit key, SHA384 hashing and MGF1+SHA384.
- [Version 2: Sodium Original](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version2.md)
    - ✅ Local: Symmetric Authenticated Encryption
        - XChaCha20-Poly1305 (192-bit nonce, 256-bit key, 128-bit authentication tag).
    - ✅ Public: Asymmetric Authentication (Public-Key Signatures)
        - EdDSA over Curve25519.
- [Version 3: NIST Modern](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md)
    - ✅ Local: Symmetric Authenticated Encryption
        - AES-256-CTR + HMAC-SHA384 (Encrypt-then-MAC).
    - ✅ Public: Asymmetric Authentication (Public-Key Signatures)
        - ECDSA over NIST P-384, with SHA-384, using [RFC 6979 deterministic k-values](https://datatracker.ietf.org/doc/html/rfc6979).
- [Version 4: Sodium Modern](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md)
    - ✅ Local: Symmetric Authenticated Encryption
        - XChaCha20 + BLAKE2b-MAC (Encrypt-then-MAC).
    - ✅ Public: Asymmetric Authentication (Public-Key Signatures)
        - EdDSA over Curve25519.

In addition, PySETO also supports [PASERK (Platform-Agnostic Serialized Keys)](https://github.com/paseto-standard/paserk).

See [Document](https://pyseto.readthedocs.io/en/stable/) for details.

## Installation

You can install PySETO with pip:

```sh
$ pip install pyseto
```

## Usage

You can use it as follows:

### v4.public

`v4.public` is one of current PASETO versions to be used for asymmetric authentication (public key signatures).

```py
import pyseto
from pyseto import Key

private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"

private_key = Key.new(version=4, type="public", key=private_key_pem)
token = pyseto.encode(private_key, b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}')

public_key = Key.new(version=4, type="public", key=public_key_pem)
decoded = pyseto.decode(public_key, token)

assert token == b'v4.public.eyJkYXRhIjogInRoaXMgaXMgYSBzaWduZWQgbWVzc2FnZSIsICJleHAiOiAiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9l1YiKei2FESvHBSGPkn70eFO1hv3tXH0jph1IfZyEfgm3t1DjkYqD5r4aHWZm1eZs_3_bZ9pBQlZGp0DPSdzDg'
assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
```

### v4.local

`v4.local` is one of current PASETO versions to be used for symmetric authenticated encryption.

```py
import pyseto
from pyseto import Key

key = Key.new(version=4, type="local", key=b"our-secret")
token = pyseto.encode(key, b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}')

decoded = pyseto.decode(key, token)
assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
```

### PASERK

As shown in the examples above, the `pyseto.Key` used for encryption and signature can be generated from PASERK or converted to PASERK (or PASERK ID) as follow:

```py
import pyseto
from pyseto import Key

# pyseto.Key can be generated from PASERK.
private_key = Key.from_paserk("k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Q")
public_key = Key.from_paserk("k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI")

token = pyseto.encode(private_key, b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}')
decoded = pyseto.decode(public_key, token)

assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'

# PASERK can be derived from pyseto.Key.
assert private_key.to_paserk() == "k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog"
assert public_key.to_paserk() == "k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI"

# PASERK ID can also be derived from pyseto.Key.
assert private_key.to_paserk_id() == "k4.sid.9gZFsAQuXhu9lif2pV3rCDjOewsMF4qb4RHGhc0zUklt"
assert public_key.to_paserk_id() == "k4.pid.yh4-bJYjOYAG6CWy0zsfPmpKylxS7uAWrxqVmBN2KAiJ"
```

## API Reference

See [Document](https://pyseto.readthedocs.io/en/stable/api.html).

## Tests

You can run tests from the project root after cloning with:

```sh
$ tox
```
