# PySETO - A Python implementation of PASETO

PySETO is a [PASETO (Platform-Agnostic SEcurity TOkens)](https://paseto.io/) implementation written in Python which supports all of the versions and purposes below.

- [Version 1: NIST Compatibility](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version1.md)
    - Local: Symmetric Authenticated Encryption
        - AES-256-CTR + HMAC-SHA384 (Encrypt-then-MAC).
    - Public: Asymmetric Authentication (Public-Key Signatures)
        - RSASSA-PSS with 2048-bit key, SHA384 hashing and MGF1+SHA384.
- [Version 2: Sodium Original](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version2.md)
    - Local: Symmetric Authenticated Encryption
        - XChaCha20-Poly1305 (192-bit nonce, 256-bit key, 128-bit authentication tag).
    - Public: Asymmetric Authentication (Public-Key Signatures)
        - EdDSA over Curve25519.
- [Version 3: NIST Modern](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md)
    - Local: Symmetric Authenticated Encryption
        - AES-256-CTR + HMAC-SHA384 (Encrypt-then-MAC).
    - Public: Asymmetric Authentication (Public-Key Signatures)
        - ECDSA over NIST P-384, with SHA-384, using [RFC 6979 deterministic k-values](https://datatracker.ietf.org/doc/html/rfc6979).
- [Version 4: Sodium Modern](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md)
    - Local: Symmetric Authenticated Encryption
        - XChaCha20 + BLAKE2b-MAC (Encrypt-then-MAC).
    - Public: Asymmetric Authentication (Public-Key Signatures)
        - EdDSA over Curve25519.

You can install PySETO with pip:

```sh
$ pip install pyseto
```

And then, you can use it as follows:

```py
>>> import pyseto
>>> from pyseto import Key
>>> secret_key_pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
>>> public_key_pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"
>>> secret_key = Key.new("v4", "public", secret_key_pem)
>>> token = pyseto.encode(secret_key, '{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}')
>>> token
b'v4.public.eyJkYXRhIjogInRoaXMgaXMgYSBzaWduZWQgbWVzc2FnZSIsICJleHAiOiAiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9l1YiKei2FESvHBSGPkn70eFO1hv3tXH0jph1IfZyEfgm3t1DjkYqD5r4aHWZm1eZs_3_bZ9pBQlZGp0DPSdzDg'
>>> public_key = Key.new("v4", "public", public_key_pem)
>>> decoded = pyseto.decode(public_key, token)
>>> decoded
b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}'
```
