PASERK Usage Examples
=====================

`PASERK (Platform-Agnostic Serialized Keys)`_ is an extension to PASETO that provides key-wrapping and serialization.

This page shows various examples to use PySETO with PASERK.

.. contents::
   :local:

Serializing/Deserializing PASERK
--------------------------------

``pyseto.Key`` used for encryption and signature can be generated from PASERK or converted to PASERK as follows:

.. code-block:: python

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

Serializing PASERK ID
---------------------

``pyseto.Key`` can also be converted to PASERK ID as follows:

.. code-block:: python

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

Key Wrapping
------------

If you call ``to_paserk`` with ``wrapping_key``, you can get a wrapped (encrypted) PASERK with the wrapping key.
The wrapped PASERK can be decrypted by calling ``from_paserk`` with ``wrapping key``.

In case of ``local-wrap.pie``:

.. code-block:: python

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

In case of ``secret-wrap.pie``:

.. code-block:: python

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

Password-based Key Encryption
-----------------------------

If you call ``to_paserk`` with ``password``, you can get a wrapped (encrypted) PASERK with the password.
The wrapped PASERK can be decrypted by calling ``from_paserk`` with ``passwrod``.

In case of ``local-pw``:

.. code-block:: python

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

In case of ``secret-pw``:

.. code-block:: python

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

Asymmetric Encryption
---------------------

At this time, PySETO supports asymmetric encryption (key sealing) for `v2` and `v4`.

.. code-block:: python

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

.. _`PASERK (Platform-Agnostic Serialized Keys)`: https://github.com/paseto-standard/paserk
