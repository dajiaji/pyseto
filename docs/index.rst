Welcome to PySETO
=================

PySETO is a `PASETO (Platform-Agnostic SEcurity TOkens)`_ implementation written
in Python which supports all of the versions and purposes below:

- `Version 4: Sodium Modern`_
    - ✅ Local: Symmetric Authenticated Encryption
        - XChaCha20 + BLAKE2b-MAC (Encrypt-then-MAC).
    - ✅ Public: Asymmetric Authentication (Public-Key Signatures)
        - EdDSA over Curve25519.
- `Version 3: NIST Modern`_
    - ✅ Local: Symmetric Authenticated Encryption
        - AES-256-CTR + HMAC-SHA384 (Encrypt-then-MAC).
    - ✅ Public: Asymmetric Authentication (Public-Key Signatures)
        - ECDSA over NIST P-384, with SHA-384, using `RFC 6979 deterministic k-values`_
- `Version 2: Sodium Original`_
    - ✅ Local: Symmetric Authenticated Encryption
        - XChaCha20-Poly1305 (192-bit nonce, 256-bit key, 128-bit authentication tag).
    - ✅ Public: Asymmetric Authentication (Public-Key Signatures)
        - EdDSA over Curve25519.
- `Version 1: NIST Compatibility`_
    - ✅ Local: Symmetric Authenticated Encryption
        - AES-256-CTR + HMAC-SHA384 (Encrypt-then-MAC).
    - ✅ Public: Asymmetric Authentication (Public-Key Signatures)
        - RSASSA-PSS with 2048-bit key, SHA384 hashing and MGF1+SHA384.

In addition, PySETO also supports `PASERK (Platform-Agnostic Serialized Keys)`_.

You can install PySETO with pip:

.. code-block:: console

    $ pip install pyseto


And then, you can use it as follows:


v4.public
---------

.. code-block:: pycon

    >>> import pyseto
    >>> from pyseto import Key
    >>> secret_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
    >>> public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"
    >>> secret_key = Key.new(version=4, purpose="public", key=secret_key_pem)
    >>> token = pyseto.encode(
    ...     secret_key,
    ...     '{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
    ... )
    >>> token
    B'v4.public.eyJkYXRhIjogInRoaXMgaXMgYSBzaWduZWQgbWVzc2FnZSIsICJleHAiOiAiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9l1YiKei2FESvHBSGPkn70eFO1hv3tXH0jph1IfZyEfgm3t1DjkYqD5r4aHWZm1eZs_3_bZ9pBQlZGp0DPSdzDg'
    >>> public_key = Key.new(4, "public", public_key_pem)
    >>> decoded = pyseto.decode(public_key, token)
    >>> decoded.payload
    B'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'

v4.local
--------

.. code-block:: pycon

    >>> import pyseto
    >>> from pyseto import Key
    >>> key = Key.new(version=4, purpose="local", key=b"our-secret")
    >>> token = pyseto.encode(
    ...     key, '{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
    ... )
    >>> token
    b'v4.local.VXJUUePf8zL1670zhOmbO7eRdccapuXlf76fRCkntiRauk2qQFOaBQOk4ISSRXQZvcGG2C5H74ShLzoU3YorK4xdfjHBj4ESoRB5mt1FWf8MEXoDQiIHQ4WDyMR57ferhaKJM6FwgcwM2xINWy1xCSFz5f7al0c8RUnd4xO_42beR83ye0jRYg'
    >>> decoded = pyseto.decode(key, token)
    >>> decoded.payload
    b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'


Index
-----

.. toctree::
   :maxdepth: 2

   installation
   paseto_usage
   paserk_usage
   api
   changes

.. _`PASETO (Platform-Agnostic SEcurity TOkens)`: https://paseto.io/
.. _`Version 1: NIST Compatibility`: https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version1.md
.. _`Version 2: Sodium Original`: https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version2.md
.. _`Version 3: NIST Modern`: https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md
.. _`Version 4: Sodium Modern`: https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md
.. _`RFC 6979 deterministic k-values`: https://datatracker.ietf.org/doc/html/rfc6979
.. _`PASERK (Platform-Agnostic Serialized Keys)`: https://github.com/paseto-standard/paserk.
