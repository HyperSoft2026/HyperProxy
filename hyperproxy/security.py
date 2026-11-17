"""Small security primitives used by HyperProxy."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
from collections.abc import Iterable


SCRYPT_N = 1 << 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32


def hash_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Return (salt, scrypt_hash) for a password."""
    if not isinstance(password, str) or not password:
        raise ValueError("Password must not be empty")
    salt = salt or os.urandom(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
    )
    return salt, digest


def verify_password(password: str, salt: bytes, expected_hash: bytes) -> bool:
    """Constant-time password verification."""
    if not password or not salt or not expected_hash:
        return False
    try:
        _, candidate = hash_password(password, salt)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate, expected_hash)


def is_public_ip(value: str) -> bool:
    """Only permit globally routable unicast addresses as proxy destinations."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global and not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def parse_allowed_ports(value: str | Iterable[int] | None) -> frozenset[int]:
    """Parse a comma-separated port list and reject invalid entries."""
    if value is None or value == "":
        return frozenset({80, 443, 5222})
    if isinstance(value, str):
        raw_ports = [part.strip() for part in value.split(",") if part.strip()]
    else:
        raw_ports = list(value)
    ports: set[int] = set()
    for raw in raw_ports:
        try:
            port = int(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid port value: {raw!r}") from exc
        if not 1 <= port <= 65535:
            raise ValueError(f"Port out of range: {port}")
        ports.add(port)
    if not ports:
        raise ValueError("At least one allowed destination port is required")
    return frozenset(ports)
