Usage Examples
==============

The following is a simple sample code using PySETO:

.. code-block:: pycon

    >>> import pyseto
    >>> from pyseto import Key
    >>> secret_key_pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
    >>> public_key_pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"
    >>> secret_key = Key.new("v4", "public", secret_key_pem)
    >>> token = pyseto.encode(
    ...     secret_key,
    ...     '{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
    ... )
    >>> token
    B'v4.public.eyJkYXRhIjogInRoaXMgaXMgYSBzaWduZWQgbWVzc2FnZSIsICJleHAiOiAiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9l1YiKei2FESvHBSGPkn70eFO1hv3tXH0jph1IfZyEfgm3t1DjkYqD5r4aHWZm1eZs_3_bZ9pBQlZGp0DPSdzDg'
    >>> public_key = Key.new("v4", "public", public_key_pem)
    >>> decoded = pyseto.decode(public_key, token)
    >>> decoded.payload
    B'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'

This page shows various examples to use PySETO.

.. contents::
   :local:

v4.local
--------

.. code-block:: python

    import pyseto
    from pyseto import Key

    key = Key.new("v4", "local", b"our-secret")
    token = pyseto.encode(
        key, '{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
    )

    decoded = pyseto.decode(key, token)

    assert (
        decoded.payload
        == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
    )
    assert decoded.footer == b""
    assert decoded.version == "v4"
    assert decoded.purpose == "local"

v4.public
---------

.. code-block:: python

    import pyseto
    from pyseto import Key

    secret_key_pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
    public_key_pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"

    secret_key = Key.new("v4", "public", secret_key_pem)
    token = pyseto.encode(
        secret_key,
        '{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
    )

    public_key = Key.new("v4", "public", public_key_pem)
    decoded = pyseto.decode(public_key, token)

    assert (
        decoded.payload
        == b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
    )
    assert decoded.footer == b""
    assert decoded.version == "v4"
    assert decoded.purpose == "public"

v3.local
--------

Under Construction

v3.public
---------

Under Construction


v2.local
--------

Under Construction

v2.public
---------

Under Construction

v1.local
--------

Under Construction

v1.public
---------

Under Construction
