# PySETO - A Python implementation of PASETO

[![PyPI version](https://badge.fury.io/py/pyseto.svg)](https://badge.fury.io/py/pyseto)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pyseto)
[![Documentation Status](https://readthedocs.org/projects/pyseto/badge/?version=latest)](https://pyseto.readthedocs.io/en/latest/?badge=latest)
![Github CI](https://github.com/dajiaji/pyseto/actions/workflows/python-package.yml/badge.svg)
[![codecov](https://codecov.io/gh/dajiaji/pyseto/branch/main/graph/badge.svg?token=QN8GXEYEP3)](https://codecov.io/gh/dajiaji/pyseto)


PySETO is a [PASETO (Platform-Agnostic SEcurity TOkens)](https://paseto.io/) implementation written in Python which supports all of the versions and purposes below.

- [Version 4: Sodium Modern](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md)
    - ✅ Local: Symmetric Authenticated Encryption
        - XChaCha20 + BLAKE2b-MAC (Encrypt-then-MAC).
    - ✅ Public: Asymmetric Authentication (Public-Key Signatures)
        - EdDSA over Curve25519.
- [Version 3: NIST Modern](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md)
    - ✅ Local: Symmetric Authenticated Encryption
        - AES-256-CTR + HMAC-SHA384 (Encrypt-then-MAC).
    - ✅ Public: Asymmetric Authentication (Public-Key Signatures)
        - ECDSA over NIST P-384, with SHA-384, using [RFC 6979 deterministic k-values](https://datatracker.ietf.org/doc/html/rfc6979).
- [Version 2: Sodium Original](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version2.md)
    - ✅ Local: Symmetric Authenticated Encryption
        - XChaCha20-Poly1305 (192-bit nonce, 256-bit key, 128-bit authentication tag).
    - ✅ Public: Asymmetric Authentication (Public-Key Signatures)
        - EdDSA over Curve25519.
- [Version 1: NIST Compatibility](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version1.md)
    - ✅ Local: Symmetric Authenticated Encryption
        - AES-256-CTR + HMAC-SHA384 (Encrypt-then-MAC).
    - ✅ Public: Asymmetric Authentication (Public-Key Signatures)
        - RSASSA-PSS with 2048-bit key, SHA384 hashing and MGF1+SHA384.

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

private_key = Key.new(version=4, purpose="public", key=private_key_pem)
token = pyseto.encode(private_key, b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}')

public_key = Key.new(version=4, purpose="public", key=public_key_pem)
decoded = pyseto.decode(public_key, token)

assert token == b'v4.public.eyJkYXRhIjogInRoaXMgaXMgYSBzaWduZWQgbWVzc2FnZSIsICJleHAiOiAiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9l1YiKei2FESvHBSGPkn70eFO1hv3tXH0jph1IfZyEfgm3t1DjkYqD5r4aHWZm1eZs_3_bZ9pBQlZGp0DPSdzDg'
assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
```

### v4.local

`v4.local` is one of current PASETO versions to be used for symmetric authenticated encryption.

```py
import pyseto
from pyseto import Key

key = Key.new(version=4, purpose="local", key=b"our-secret")
token = pyseto.encode(key, b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}')

decoded = pyseto.decode(key, token)
assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
```

## Usage with PASERK

[PASERK (Platform-Agnostic Serialized Keys)](https://github.com/paseto-standard/paserk) is an extension to PASETO that provides key-wrapping and serialization.

### Serializing/Deserializing PASERK

As shown in the examples above, the `pyseto.Key` used for encryption and signature can be generated from PASERK or converted to PASERK as follows:

```py
import pyseto
from pyseto import Key

# pyseto.Key can be generated from PASERK.
symmetric_key = Key.new(version=4, purpose="local", key=b"our-secret")
private_key = Key.from_paserk("k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog")
public_key = Key.from_paserk("k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI")

token = pyseto.encode(private_key, b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}')
decoded = pyseto.decode(public_key, token)

assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'

# PASERK can be derived from pyseto.Key.
assert symmetric_key.to_paserk() == "k4.local.b3VyLXNlY3JldA"
assert private_key.to_paserk() == "k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog"
assert public_key.to_paserk() == "k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI"
```

### Serializing PASERK ID

`pyseto.Key` can also be converted to PASERK ID as follows:

```py
import pyseto
from pyseto import Key

# pyseto.Key can be generated from PASERK.
symmetric_key = Key.new(version=4, purpose="local", key=b"our-secret")
private_key = Key.from_paserk("k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog")
public_key = Key.from_paserk("k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI")

# PASERK ID can be derived from pyseto.Key.
assert symmetric_key.to_paserk_id() == "k4.lid._D6kgTzxgiPGk35gMj9bukgj4En2H94u22wVX9zaoh05"
assert private_key.to_paserk() == "k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog"
assert public_key.to_paserk_id() == "k4.pid.yh4-bJYjOYAG6CWy0zsfPmpKylxS7uAWrxqVmBN2KAiJ"
```

### Key Wrapping

If you call `to_paserk` with `wrapping_key`, you can get a wrapped (encrypted) PASERK with the wrapping key.
The wrapped PASERK can be decrypted by calling `from_paserk` with `wrapping key`.

In case of `local-wrap.pie`:

```py
import pyseto
from pyseto import Key

raw_key = Key.new(version=4, purpose="local", key=b"our-secret")
wrapping_key = token_bytes(32)
wpk = raw_key.to_paserk(wrapping_key=wrapping_key)

# assert wpk == "k4.local-wrap.pie.TNKEwC4K1xBcgJ_GiwWAoRlQFE33HJO3oN9DHEZ05pieSCd-W7bgAL64VG9TZ_pBkuNBFHNrfOGHtnfnhYGdbz5-x3CxShhPJxg"

unwrapped_key = Key.from_paserk(wpk, wrapping_key=wrapping_key)
token = pyseto.encode(raw_key, b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}')
decoded = pyseto.decode(unwrapped_key, token)
assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
```

In case of `secret-wrap.pie`:

```py
import pyseto
from pyseto import Key

raw_private_key = Key.from_paserk(
    "k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog"
)
public_key = Key.from_paserk(
    "k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI"
)
wrapping_key = token_bytes(32)
wpk = raw_private_key.to_paserk(wrapping_key=wrapping_key)

# assert wpk == "k4.secret-wrap.pie.excv7V4-NaECy5hpji-tkSkMvyjsAgNxA-mGALgdjyvGNyDlTb89bJ35R1e3tILgbMpEW5WXMXzySe2T-sBz-ZAcs1j7rbD3ZWvsBTM6K5N9wWfAxbR4ppCXH_H5__9yY-kBaF2NimyAJyduhOhSmqLm6TTSucpAOakEJOXePW8"

unwrapped_private_key = Key.from_paserk(wpk, wrapping_key=wrapping_key)
token = pyseto.encode(unwrapped_private_key, b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}')
decoded = pyseto.decode(public_key, token)
assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
```

### Password-based Key Encryption

If you call `to_paserk` with `password`, you can get a wrapped (encrypted) PASERK with the password.
The wrapped PASERK can be decrypted by calling `from_paserk` with `passwrod`.

In case of `local-pw`:

```py
import pyseto
from pyseto import Key

raw_key = Key.new(version=4, purpose="local", key=b"our-secret")
wpk = raw_key.to_paserk(password="our-secret")

# assert wpk == "k4.local-pw.HrCs9Pu-2LB0l7jkHB-x2gAAAAAA8AAAAAAAAgAAAAGttW0IHZjQCHJdg-Vc3tqO_GSLR4vzLl-yrKk2I-l8YHj6jWpC0lQB2Z7uzTtVyV1rd_EZQPzHdw5VOtyucP0FkCU"

unwrapped_key = Key.from_paserk(wpk, password="our-secret")
token = pyseto.encode(raw_key, b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}')
decoded = pyseto.decode(unwrapped_key, token)
assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
```

In case of `secret-pw`:

```py
import pyseto
from pyseto import Key

raw_private_key = Key.from_paserk(
    "k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog"
)
public_key = Key.from_paserk(
    "k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI"
)
wpk = raw_private_key.to_paserk(password="our-secret")

# assert wpk == "k4.secret-pw.MEMW4K1MaD5nWigCLyEyFAAAAAAA8AAAAAAAAgAAAAFU-tArtryNVjS2n2hCYiM11V6tOyuIog69Bjb0yNZanrLJ3afGclb3kPzQ6IhK8ob9E4QgRdEALGWCizZ0RCPFF_M95IQDfmdYKC0Er656UgKUK4UKG9JlxP4o81UwoJoZYz_D1zTlltipEa5RiNvUtNU8vLKoGSY"

unwrapped_private_key = Key.from_paserk(wpk, password="our-secret")
token = pyseto.encode(unwrapped_private_key, b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}')
decoded = pyseto.decode(public_key, token)
assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
```

### Asymmetric Encryption

Not supported yet.

## API Reference

See [Document](https://pyseto.readthedocs.io/en/stable/api.html).

## Tests

You can run tests from the project root after cloning with:

```sh
$ tox
```
