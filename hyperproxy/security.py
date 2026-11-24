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

# Source: https://core.telegram.org/resources/cidr.txt
# Keep this list synchronized with Telegram's published server networks.
DEFAULT_TELEGRAM_CIDRS = (
    "91.105.192.0/23",
    "91.108.4.0/22",
    "91.108.8.0/22",
    "91.108.12.0/22",
    "91.108.16.0/22",
    "91.108.20.0/22",
    "91.108.56.0/22",
    "149.154.160.0/20",
    "185.76.151.0/24",
    "2001:67c:4e8::/48",
    "2001:b28:f23c::/48",
    "2001:b28:f23d::/48",
    "2001:b28:f23f::/48",
    "2a0a:f280::/32",
)


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


def parse_telegram_networks(value: str | Iterable[str] | None = None) -> tuple:
    """Parse Telegram-only destination CIDRs; defaults to Telegram's published ranges."""
    if value is None or value == "":
        raw_networks = DEFAULT_TELEGRAM_CIDRS
    elif isinstance(value, str):
        raw_networks = tuple(part.strip() for part in value.split(",") if part.strip())
    else:
        raw_networks = tuple(str(part).strip() for part in value if str(part).strip())

    networks = []
    for raw in raw_networks:
        try:
            networks.append(ipaddress.ip_network(raw, strict=True))
        except ValueError as exc:
            raise ValueError(f"Invalid Telegram destination CIDR: {raw!r}") from exc
    if not networks:
        raise ValueError("Telegram destination CIDR allowlist cannot be empty")
    return tuple(networks)


def is_allowed_telegram_ip(value: str, networks: Iterable) -> bool:
    """Allow only public IPs inside Telegram's explicitly permitted network ranges."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if not is_public_ip(str(address)):
        return False
    return any(address.version == network.version and address in network for network in networks)


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
