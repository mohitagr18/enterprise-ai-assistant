"""
Argon2id-based password hashing and verification.

Chapter 11 — Agent Identity & Authentication: Password Hashing.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Initialize the Argon2 password hasher. Uses secure default parameters.
_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """
    Hash a password using Argon2id with a unique, cryptographically strong salt.
    """
    return _hasher.hash(password)


def verify_password(hash_str: str, password: str) -> bool:
    """
    Verify a password against an Argon2id hash.
    Returns True if valid, False otherwise.
    """
    try:
        return _hasher.verify(hash_str, password)
    except VerifyMismatchError:
        return False


def validate_password_strength(password: str) -> bool:
    """
    Validate that a password meets minimum strength requirements:
    - At least 8 characters (12+ recommended).
    - No more than 128 characters to prevent hashing CPU exhaustion denial of service.
    """
    return 8 <= len(password) <= 128
