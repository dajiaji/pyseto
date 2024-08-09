# PySETO - A Python implementation of PASETO/PASERK

[![PyPI version](https://badge.fury.io/py/pyseto.svg)](https://badge.fury.io/py/pyseto)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pyseto)
[![Documentation Status](https://readthedocs.org/projects/pyseto/badge/?version=latest)](https://pyseto.readthedocs.io/en/latest/?badge=latest)
![Github CI](https://github.com/dajiaji/pyseto/actions/workflows/python-package.yml/badge.svg)
[![codecov](https://codecov.io/gh/dajiaji/pyseto/branch/main/graph/badge.svg?token=QN8GXEYEP3)](https://codecov.io/gh/dajiaji/pyseto)
$ pip install pyseto

PySETO is a [PASETO (Platform-Agnostic SEcurity TOkens)](https://paseto.io/)/[PASERK (Platform-Agnostic Serialized Keys)](https://github.com/paseto-standard/paserk) implementation written in Python
which supports all of the versions ([v1](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version1.md),
[v2](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version2.md),
[v3](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md) and
[v4](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md)) and purposes (`public` and `local`)
and has passed all of [the official tests](https://github.com/paseto-standard/test-vectors).

You can install PySETO with pip:

```sh
$ pip install pyseto
```
import pyseto
from pyseto import Key

private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"


# Create a PASETO token.
private_key = Key.new(version=4, purpose="public", key=private_key_pem)
token = pyseto.encode(
    private_key,
    b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
)

# Decode and verify a PASETO token.
public_key = Key.new(version=4, purpose="public", key=public_key_pem)
decoded = pyseto.decode(public_key, token)

assert (
    token
    == b"v4.public.eyJkYXRhIjogInRoaXMgaXMgYSBzaWduZWQgbWVzc2FnZSIsICJleHAiOiAiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9l1YiKei2FESvHBSGPkn70eFO1hv3tXH0jph1IfZyEfgm3t1DjkYqD5r4aHWZm1eZs_3_bZ9pBQlZGp0DPSdzDg"
)
assert (
    decoded.payload
    == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
)
PySETO can be used in ease as follows (in case of `v4.public`):

```py
import pyseto
from pyseto import Key

private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"

decoded.payload
# Create a PASETO token.
private_key = Key.new(version=4, purpose="public", key=private_key_pem)
token = pyseto.encode(
    private_key,
    b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
)import pyseto
from pyseto import Key

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
assert (
    decoded.payload
    == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
)import pyseto
from pyseto import Key

key = Key.new(version=4, purpose="local", key=b"our-secret")
token = pyseto.encode(
    key, b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
)

decoded = pyseto.decode(key, token)

assert (
    decoded.payload
    == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
)

# Decode and verify a PASETO token.
public_key = Key.new(version=4, purpose="public", key=public_key_pem)
decoded = pyseto.decode(public_key, token)

assert (
    token
    == b"v4.public.eyJkYXRhIjogInRoaXMgaXMgYSBzaWduZWQgbWVzc2FnZSIsICJleHAiOiAiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9l1YiKei2FESvHBSGPkn70eFO1hv3tXH0jph1IfZyEfgm3t1DjkYqD5r4aHWZm1eZs_3_bZ9pBQlZGp0DPSdzDg"
)
assert (
    decoded.payload
    == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
)
```import pyseto
from pyseto import Key

key = Key.new(version=4, purpose="local", key=b"our-secret")
token = pyseto.encode(
    key, b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
)decoded.payload

decoded = pyseto.decode(key, token)

assert (
    decoded.payload
    == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
)import pyseto
from pyseto import Key

private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"

import json
import pyseto
from pyseto import Key

private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"

private_key = Key.new(version=4, purpose="public", key=private_key_pem)
public_key = Key.new(version=4, purpose="public", key=public_key_pem)
token = pyseto.encode(
    private_key,
    {"data": "this is a signed message"},
    footer={"kid": public_key.to_paserk_id()},
    serializer=json,
    exp=3600,
)import json
import pyseto
from pyseto import Key, Paseto

private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"

private_key = Key.new(version=4, purpose="public", key=private_key_pem)
paseto = Paseto.new(
    exp=3600, include_iat=True
)  # Default values are exp=0(not specified) and including_iat=False
token = paseto.encode(
    private_key,
    {"data": "this is a signed message"},
    serializer=json,
)

public_key = Key.new(version=4, purpose="public", key=public_key_pem)
decoded = pyseto.decode(public_key, token, deserializer=json)

assert decoded.payload["data"] == "this is a signed message"
assert decoded.payload["iat"] == "2021-11-11T00:00:00+00:00"
assert decoded.payload["exp"] == "2021-11-11T01:00:00+00:00"

decoded = pyseto.decode(public_key, token, deserializer=json)

assert decoded.payload["data"] == "this is a signed message"
assert decoded.payload["exp"] == "2021-11-11T00:00:00+00:00"
assert decoded.footer["kid"] == "k4.pid.yh4-bJYjOYAG6CWy0zsfPmpKylxS7uAWrxqVmBN2KAiJ"
# Create a PASETO token.
private_key = Key.new(version=4, purpose="public", key=private_key_pem)
token = pyseto.encode(private_key, b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}')

# Decode and verify a PASETO token.
public_key = Key.new(version=4, purpose="public", key=public_key_pem)
decoded = pyseto.decode(public_key, token)

assert token == b'v4.public.eyJkYXRhIjogInRoaXMgaXMgYSBzaWduZWQgbWVzc2FnZSIsICJleHAiOiAiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9l1YiKei2FESvHBSGPkn70eFO1hv3tXH0jph1IfZyEfgm3t1DjkYqD5r4aHWZm1eZs_3_bZ9pBQlZGp0DPSdzDg'
assert decoded.payload == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'

See following contents or [Documentation](https://pyseto.readthedocs.io/en/stable/) for details.

## Index

- [Installation](#installation)
- [Supported PASETO Versions](#supported-paseto-versions)
- [Supported PASERK Types](#supported-paserk-types)
- [PASETO Usage](#paseto-usage)
    - [Basic usage: v4.public](#basic-usage-v4public)
    - [Basic usage: v4.local](#basic-usage-v4local)
    - [Using serializer/deserializer for payload and footer](#using-serializerdeserializer-for-payload-and-footer)
    - [Using Paseto class for handling registered claims](#using-paseto-class-for-handling-registered-claims)
- [PASERK Usage](#paserk-usage)
    - [Serializing/Deserializing PASERK](#serializingdeserializing-paserk)
    - [Serializing PASERK ID](#serializing-paserk-id)
    - [Key Wrapping](#key-wrapping)
    - [Password-based Key Encryption](#password-based-key-encryption)
    - [Asymmetric Encryption](#asymmetric-encryption)
- [API Reference](#api-reference)
- [Tests](#tests)
- [Contributing](#contributing)

## Installation

You can install PySETO with pip:

```sh
$ pip install pyseto
```import pyseto
from pyseto import Key

# pyseto.Key can be generated from PASERK.
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

assert (
    decoded.payload
    == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
)

# PASERK can be derived from pyseto.Key.
assert symmetric_key.to_paserk() == "k4.local.b3VyLXNlY3JldA"
assert (
    private_key.to_paserk()
    == "k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog"
)
assert public_key.to_paserk() == "k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI"

## Supported PASETO Versions

PySETO supports all of PASETO versions and purposes below:


|          |  v4  |  v3  |  v2  |  v1  |
| ---------| ---- | ---- | ---- | ---- |
| `local`  |  ✅  |  ✅  |  ✅  |  ✅  |
| `public` |  ✅  |  ✅  |  ✅  |  ✅  |


## Supported PASERK Types

PySETO also supports [PASERK (Platform-Agnostic Serialized Keys)](https://github.com/paseto-standard/paserk).
Currently, following PASERK types are supported:


|               |  v4  |  v3  |  v2  |  v1  |
| ------------- | ---- | ---- | ---- | ---- |
| `lid`         |  ✅  |  ✅  |  ✅  |  ✅  |
| `sid`         |  ✅  |  ✅  |  ✅  |  ✅  |
| `pid`         |  ✅  |  ✅  |  ✅  |  ✅  |
| `local`       |  ✅  |  ✅  |  ✅  |  ✅  |
| `secret`      |  ✅  |  ✅  |  ✅  |  ✅  |
| `public`      |  ✅  |  ✅  |  ✅  |  ✅  |
| `seal`        |  ✅  |      |  ✅  |      |
| `local-wrap`  |  ✅  |  ✅  |  ✅  |  ✅  |
| `secret-wrap` |  ✅  |  ✅  |  ✅  |  ✅  |
| `local-pw`    |  ✅  |  ✅  |  ✅  |  ✅  |
| `secret-pw`   |  ✅  |  ✅  |  ✅  |  ✅  |


## PASETO Usage

By using this PySETO, you can easily create, decode and verify PASETO tokens. Here are sample codes that handle version 4 PySETO tokens.

Please refer to [the Documentation](https://pyseto.readthedocs.io/en/stable/) for all usage examples including other versions.

### Basic usage: v4.public

`v4.public` is one of current PASETO versions to be used for asymmetric authentication (public key signatures).

```py
import pyseto
from pyseto import Key

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
assert (
    decoded.payload
    == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
)
```import pyseto
from pyseto import Key

# pyseto.Key can be generated from PASERK.
symmetric_key = Key.new(version=4, purpose="local", key=b"our-secret")
private_key = Key.from_paserk(
    "k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog"
)
public_key = Key.from_paserk("k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI")

# PASERK ID can be derived from pyseto.Key.
assert (
    symmetric_key.to_paserk_id()
    == "k4.lid._D6kgTzxgiPGk35gMj9bukgj4En2H94u22wVX9zaoh05"
)
assert (
    private_key.to_paserk()
    == "k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog"
)
assert (
    public_key.to_paserk_id() == "k4.pid.yh4-bJYjOYAG6CWy0zsfPmpKylxS7uAWrxqVmBN2KAiJ"
)

### Basic usage: v4.local

`v4.local` is one of current PASETO versions to be used for symmetric authenticated encryption.

```py
import pyseto
from pyseto import Key

key = Key.new(version=4, purpose="local", key=b"our-secret")
token = pyseto.encode(
    key, b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
)

decoded = pyseto.decode(key, token)

assert (
    decoded.payload
    == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
)
```pyseto.Key

### Using serializer/deserializer for payload and footer

By using `serializer` and `deserializer`, you can encode/decode a dict-typed payload and footer included in PASETO tokens into an arbitrary format.
The following example shows that the payload and the footer in a PASETO token are encoded/decoded as JSON formatted data.
When specifing dict-typed payload, exp parameter can be used to set the expiration time (seconds) of the token.

```py
import json
import pyseto
from pyseto import Key

private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"

private_key = Key.new(version=4, purpose="public", key=private_key_pem)
public_key = Key.new(version=4, purpose="public", key=public_key_pem)
token = pyseto.encode(
    private_key,
    {"data": "this is a signed message"},
    footer={"kid": public_key.to_paserk_id()},
    serializer=json,
    exp=3600,
)

decoded = pyseto.decode(public_key, token, deserializer=json)

assert decoded.payload["data"] == "this is a signed message"
assert decoded.payload["exp"] == "2021-11-11T00:00:00+00:00"
assert decoded.footer["kid"] == "k4.pid.yh4-bJYjOYAG6CWy0zsfPmpKylxS7uAWrxqVmBN2KAiJ"
```

### Using `Paseto` class for handling registered claims

By using `Paseto` class, you can change the default value of `exp` (the expiration date ot tokens), whether to include an `iat` claim, and other settings.

Note that `pyseto.encode()` and `pyseto.decode()` are aliases to the `encode()` and `decode()` of the global "Paseto" class instance created with the default settings.

```py
import json
import pyseto
from pyseto import Key, Paseto

private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"

private_key = Key.new(version=4, purpose="public", key=private_key_pem)
paseto = Paseto.new(
    exp=3600, include_iat=True
)  # Default values are exp=0(not specified) and including_iat=False
token = paseto.encode(
    private_key,
    {"data": "this is a signed message"},
    serializer=json,
)

public_key = Key.new(version=4, purpose="public", key=public_key_pem)
decoded = pyseto.decode(public_key, token, deserializer=json)

assert decoded.payload["data"] == "this is a signed message"
assert decoded.payload["iat"] == "2021-11-11T00:00:00+00:00"
assert decoded.payload["exp"] == "2021-11-11T01:00:00+00:00"
```

## PASERK Usage

[PASERK (Platform-Agnostic Serialized Keys)](https://github.com/paseto-standard/paserk) is an extension to PASETO that provides key-wrapping and serialization.

### Serializing/Deserializing PASERK

As shown in the examples above, the `pyseto.Key` used for encryption and signature can be generated from PASERK or converted to PASERK as follows:

```py
import pyseto
from pyseto import Key

# pyseto.Key can be generated from PASERK.
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

assert (
    decoded.payload
    == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
)

# PASERK can be derived from pyseto.Key.
assert symmetric_key.to_paserk() == "k4.local.b3VyLXNlY3JldA"
assert (
    private_key.to_paserk()
    == "k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog"
)
assert public_key.to_paserk() == "k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI"
```

### Serializing PASERK ID

`pyseto.Key` can also be converted to PASERK ID as follows:

```py
import pyseto
from pyseto import Key

# pyseto.Key can be generated from PASERK.
symmetric_key = Key.new(version=4, purpose="local", key=b"our-secret")
private_key = Key.from_paserk(
    "k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog"
)
public_key = Key.from_paserk("k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI")

# PASERK ID can be derived from pyseto.Key.
assert (
    symmetric_key.to_paserk_id()
    == "k4.lid._D6kgTzxgiPGk35gMj9bukgj4En2H94u22wVX9zaoh05"
)
assert (
    private_key.to_paserk()
    == "k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog"
)
assert (
    public_key.to_paserk_id() == "k4.pid.yh4-bJYjOYAG6CWy0zsfPmpKylxS7uAWrxqVmBN2KAiJ"
)
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
token = pyseto.encode(
    raw_key, b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
)

unwrapped_key = Key.from_paserk(wpk, wrapping_key=wrapping_key)
decoded = pyseto.decode(unwrapped_key, token)

# assert wpk == "k4.local-wrap.pie.TNKEwC4K1xBcgJ_GiwWAoRlQFE33HJO3oN9DHEZ05pieSCd-W7bgAL64VG9TZ_pBkuNBFHNrfOGHtnfnhYGdbz5-x3CxShhPJxg"
assert (
    decoded.payload
    == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
)
```

In case of `secret-wrap.pie`:

```py
import pyseto
from pyseto import Key

raw_private_key = Key.from_paserk(
    "k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog"
)
wrapping_key = token_bytes(32)
wpk = raw_private_key.to_paserk(wrapping_key=wrapping_key)
unwrapped_private_key = Key.from_paserk(wpk, wrapping_key=wrapping_key)
token = pyseto.encode(
    unwrapped_private_key,
    b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
)

public_key = Key.from_paserk("k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI")
decoded = pyseto.decode(public_key, token)

# assert wpk == "k4.secret-wrap.pie.excv7V4-NaECy5hpji-tkSkMvyjsAgNxA-mGALgdjyvGNyDlTb89bJ35R1e3tILgbMpEW5WXMXzySe2T-sBz-ZAcs1j7rbD3ZWvsBTM6K5N9wWfAxbR4ppCXH_H5__9yY-kBaF2NimyAJyduhOhSmqLm6TTSucpAOakEJOXePW8"
assert (
    decoded.payload
    == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
)
```

### Password-based Key Encryption

If you call `to_paserk` with `password`, you can get a wrapped (encrypted) PASERK with the password.
The wrapped PASERK can be decrypted by calling `from_paserk` with `passwrod`.

In case of `local-pw`:

```py
import pyseto
from pyseto import Key

raw_key = Key.new(version=4, purpose="local", key=b"our-secret")
token = pyseto.encode(
    raw_key, b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
)

wpk = raw_key.to_paserk(password="our-secret")
unwrapped_key = Key.from_paserk(wpk, password="our-secret")
decoded = pyseto.decode(unwrapped_key, token)

# assert wpk == "k4.local-pw.HrCs9Pu-2LB0l7jkHB-x2gAAAAAA8AAAAAAAAgAAAAGttW0IHZjQCHJdg-Vc3tqO_GSLR4vzLl-yrKk2I-l8YHj6jWpC0lQB2Z7uzTtVyV1rd_EZQPzHdw5VOtyucP0FkCU"
assert (
    decoded.payload
    == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
)
```

In case of `secret-pw`:

```py
import pyseto
from pyseto import Key

raw_private_key = Key.from_paserk(
    "k4.secret.tMv7Q99M4hByfZU-SnEzB_oZu32fhQQUONnhG5QqN3Qeudu7vAR8A_1wYE4AcfCYfhayi3VyJcEfAEFdDiCxog"
)
wpk = raw_private_key.to_paserk(password="our-secret")
unwrapped_private_key = Key.from_paserk(wpk, password="our-secret")
token = pyseto.encode(
    unwrapped_private_key,
    b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
)

public_key = Key.from_paserk("k4.public.Hrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI")
decoded = pyseto.decode(public_key, token)

# assert wpk == "k4.secret-pw.MEMW4K1MaD5nWigCLyEyFAAAAAAA8AAAAAAAAgAAAAFU-tArtryNVjS2n2hCYiM11V6tOyuIog69Bjb0yNZanrLJ3afGclb3kPzQ6IhK8ob9E4QgRdEALGWCizZ0RCPFF_M95IQDfmdYKC0Er656UgKUK4UKG9JlxP4o81UwoJoZYz_D1zTlltipEa5RiNvUtNU8vLKoGSY"
assert (
    decoded.payload
    == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
)
```

### Asymmetric Encryption

At this time, PySETO supports asymmetric encryption (key sealing) for `v2` and `v4`.

```py
import pyseto
from pyseto import Key

private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VuBCIEIFAF7jSCZHFgWvC8hUkXr55Az6Pot2g4zOAUxck0/6x8\n-----END PRIVATE KEY-----"
public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VuAyEAFv8IXsICYj0paznDK/99GyCsFOIGnfY87ayyNSIvSB4=\n-----END PUBLIC KEY-----"

raw_key = Key.new(version=4, purpose="local", key=b"our-secret")
token = pyseto.encode(
    raw_key,
    b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
)

sealed_key = raw_key.to_paserk(sealing_key=public_key_pem)
unsealed_key = Key.from_paserk(sealed_key, unsealing_key=private_key_pem)
decoded = pyseto.decode(unsealed_key, token)

assert (
    decoded.payload
    == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
)
```

Key searing for `v1` and `v3` have not been supported yet.


## API Reference

See [Documentation](https://pyseto.readthedocs.io/en/stable/api.html).

## Tests

You can run tests from the project root after cloning with:

```sh
$ tox
```

## Contributing

We welcome all kind of contributions, filing issues, suggesting new features or sending PRs.
