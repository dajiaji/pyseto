Changes
=======

Unreleased
----------

Version 1.0.0
-------------

Released 2021-09-25

- [Breaking Change] Remove str support for version. `#53 <https://github.com/dajiaji/pyseto/pull/53>`__
- [Breaking Change] Rename type of Key.new to purpose. `#52 <https://github.com/dajiaji/pyseto/pull/52>`__
- Add support for PASERK password-based key wrapping. `#47 <https://github.com/dajiaji/pyseto/pull/47>`__
- Add support for PASERK key wrapping. `#46 <https://github.com/dajiaji/pyseto/pull/46>`__

Version 0.7.1
-------------

Released 2021-09-18

- Make PASERK secret for Ed25519 compliant with PASERK spec. `#44 <https://github.com/dajiaji/pyseto/pull/44>`__

Version 0.7.0
-------------

Released 2021-09-16

- Add from_paserk to Key. `#41 <https://github.com/dajiaji/pyseto/pull/41>`__
- Add support for paserk lid. `#40 <https://github.com/dajiaji/pyseto/pull/40>`__
- Add support for paserk local. `#40 <https://github.com/dajiaji/pyseto/pull/40>`__
- Add to_paserk_id to KeyInterface. `#39 <https://github.com/dajiaji/pyseto/pull/39>`__
- Add to_paserk to KeyInterface. `#38 <https://github.com/dajiaji/pyseto/pull/38>`__
- Fix public key compression for v3.

Version 0.6.1
-------------

Released 2021-09-12

- Add usage examples and related tests. `#36 <https://github.com/dajiaji/pyseto/pull/36>`__

Version 0.6.0
-------------

Released 2021-09-11

- Add tests for sample code. `#34 <https://github.com/dajiaji/pyseto/pull/34>`__
- Allow int type version for Key.new. `#33 <https://github.com/dajiaji/pyseto/pull/33>`__

Version 0.5.0
-------------

Released 2021-09-11

- Add API reference about Token. `#30 <https://github.com/dajiaji/pyseto/pull/30>`__
- Add support for multiple keys on decode. `#29 <https://github.com/dajiaji/pyseto/pull/29>`__

Version 0.4.0
-------------

Released 2021-09-10

- Add tests for public and fix error message. `#26 <https://github.com/dajiaji/pyseto/pull/26>`__
- Add tests for local and fix error message. `#25 <https://github.com/dajiaji/pyseto/pull/25>`__
- Add tests for Token. `#24 <https://github.com/dajiaji/pyseto/pull/24>`__
- Add tests for Key and fix checking argument. `#22 <https://github.com/dajiaji/pyseto/pull/22>`__
- Add docstrings for KeyInterface. `#21 <https://github.com/dajiaji/pyseto/pull/21>`__

Version 0.3.2
-------------

Released 2021-09-07

- Add API reference. `#17 <https://github.com/dajiaji/pyseto/pull/17>`__

Version 0.3.1
-------------

Released 2021-09-06

- Fix readthedocs build error. `#13 <https://github.com/dajiaji/pyseto/pull/13>`__

Version 0.3.0
-------------

Released 2021-09-06

- Add docs. `#10 <https://github.com/dajiaji/pyseto/pull/10>`__
- Add Key.from_asymmetric_key_params. `#8 <https://github.com/dajiaji/pyseto/pull/8>`__
- Make NotSupportedError public. `#8 <https://github.com/dajiaji/pyseto/pull/8>`__

Version 0.2.0
-------------

Released 2021-09-05

- Add Token object as a response of decode(). `#6 <https://github.com/dajiaji/pyseto/pull/6>`__

Version 0.1.0
-------------

Released 2021-09-05

- First public preview release.
