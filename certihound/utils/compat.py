"""
Compatibility shims for cryptographic primitives.

On newer systems (e.g. Fedora 43 / Python 3.14 / OpenSSL 3 with the legacy
provider disabled) ``hashlib.new("md4", ...)`` raises ``ValueError: unsupported
hash type md4``. ldap3's NTLM implementation requires MD4 to compute the NT
hash, and its own fallback only imports ``Crypto.Hash.MD4`` (the legacy
pycrypto namespace). When only ``Cryptodome`` (pycryptodome) is installed, both
paths fail and authentication blows up with::

    [-] Error: unsupported hash type MD4

This module installs a best-effort ``hashlib.new`` shim that transparently
routes ``md4`` requests to pycryptodome when OpenSSL cannot provide it. Import
this module as early as possible (before ldap3 bind / NTLM) to take effect.
"""

from __future__ import annotations

import hashlib


def _load_pycryptodome_md4():
    """Return a pycryptodome MD4 module, trying both namespaces."""
    try:
        from Cryptodome.Hash import MD4  # type: ignore[import-not-found]
        return MD4
    except ImportError:
        pass
    try:
        from Crypto.Hash import MD4  # type: ignore[import-not-found]
        return MD4
    except ImportError:
        return None


def _openssl_supports_md4() -> bool:
    try:
        hashlib.new("md4")
        return True
    except (ValueError, TypeError):
        return False


_patched = False


def install_md4_shim() -> bool:
    """Monkey-patch ``hashlib.new`` to fall back to pycryptodome for MD4.

    Returns ``True`` if a shim was installed (or was already in place),
    ``False`` if no fallback is necessary or available.
    """
    global _patched
    if _patched:
        return True
    if _openssl_supports_md4():
        return False

    md4_module = _load_pycryptodome_md4()
    if md4_module is None:
        return False

    original_new = hashlib.new

    def patched_new(name, data=b"", **kwargs):
        if isinstance(name, str) and name.lower() == "md4":
            h = md4_module.new()
            if data:
                h.update(data)
            return h
        return original_new(name, data, **kwargs)

    hashlib.new = patched_new  # type: ignore[assignment]
    _patched = True
    return True
