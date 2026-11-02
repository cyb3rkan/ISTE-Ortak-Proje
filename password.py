"""
Password hashing for the user-auth layer.

We use Argon2id via ``argon2-cffi`` — a memory-hard KDF that is the current
recommended default for password storage.

Security notes:

* Plaintext passwords are **never** stored, logged, or returned. The CLI
  helper below prints only the resulting hash.
* :func:`verify_password` is exception-safe: a malformed stored hash or a
  mismatch both return ``False`` without leaking why.
* Argon2's own verification is constant-time with respect to the secret.

CLI usage (prints an Argon2 hash, suitable for
``IOC_WEB_BOOTSTRAP_ADMIN_PASSWORD_HASH``)::

    python -m ioc_enricher.web.api.security.password "YourStrongPassword"

If no argument is given the password is read interactively (never echoed).
"""
from __future__ import annotations

import sys

from argon2 import PasswordHasher
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)

# Argon2id with library defaults — a sensible, well-reviewed baseline. Tuning
# is intentionally left to the library so we do not ship hand-picked weak
# parameters.
_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """
    Return an Argon2id hash string for *password*.

    The returned value embeds the algorithm, parameters and salt, so it is
    self-describing and safe to store as-is.
    """
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    return _hasher.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Return ``True`` iff *password* matches *stored_hash*.

    Any failure mode — wrong password, malformed/empty hash, unexpected
    library error — returns ``False``. Nothing about the failure is leaked.
    """
    if not password or not stored_hash:
        return False
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception:  # noqa: BLE001 — defensive: never raise from a verify
        return False


def _cli(argv: list[str]) -> int:
    """Hash-generation helper. Prints only the hash; never the password."""
    if len(argv) > 1:
        password = argv[1]
    else:
        import getpass

        password = getpass.getpass("Password to hash: ")

    if not password:
        print("error: empty password", file=sys.stderr)
        return 2

    print(hash_password(password))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via subprocess
    raise SystemExit(_cli(sys.argv))
