"""Environment-based configuration for HyperProxy."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Mapping

from .security import parse_allowed_ports


@dataclass(frozen=True, slots=True)
class Settings:
    database_url: str
    admin_username: str
    admin_password: str
    socks_host: str = "127.0.0.1"
    socks_port: int = 4041
    router_host: str = "0.0.0.0"
    router_port: int = 4040
    health_host: str = "0.0.0.0"
    health_port: int = 8080
    mtproto_port: int = 4042
    mtproto_stats_port: int = 8888
    mtproto_workers: int = 1
    mtproto_secret: str | None = None
    mtproto_proxy_tag: str | None = None
    max_connections: int = 200
    max_connections_per_user: int = 20
    connect_timeout: float = 10.0
    auth_timeout: float = 10.0
    allowed_ports: frozenset[int] = frozenset({80, 443, 5222})

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "Settings":
        env = os.environ if environ is None else environ
        database_url = (env.get("DATABASE_URL") or env.get("POSTGRESQL_ADDON_URI") or "").strip()
        admin_username = env.get("PROXY_ADMIN_USERNAME", "").strip()
        admin_password = env.get("PROXY_ADMIN_PASSWORD", "")
        mtproto_secret = (env.get("MTPROTO_SECRET") or "").strip().lower() or None
        mtproto_proxy_tag = (env.get("MTPROTO_PROXY_TAG") or "").strip().lower() or None

        if not database_url:
            raise ValueError("Set DATABASE_URL or POSTGRESQL_ADDON_URI before starting HyperProxy")
        if not admin_username or len(admin_username) > 64:
            raise ValueError("PROXY_ADMIN_USERNAME must contain 1 to 64 characters")
        if len(admin_password) < 16:
            raise ValueError("PROXY_ADMIN_PASSWORD must be at least 16 characters")
        if mtproto_secret and not re.fullmatch(r"[0-9a-f]{32}", mtproto_secret):
            raise ValueError("MTPROTO_SECRET must be exactly 32 hexadecimal characters")
        if mtproto_proxy_tag and not mtproto_secret:
            raise ValueError("MTPROTO_PROXY_TAG requires MTPROTO_SECRET")
        if mtproto_proxy_tag and not re.fullmatch(r"[0-9a-f]{32}", mtproto_proxy_tag):
            raise ValueError("MTPROTO_PROXY_TAG must be exactly 32 hexadecimal characters")

        def integer(name: str, default: int, minimum: int, maximum: int) -> int:
            try:
                result = int(env.get(name, str(default)))
            except ValueError as exc:
                raise ValueError(f"{name} must be an integer") from exc
            if not minimum <= result <= maximum:
                raise ValueError(f"{name} must be between {minimum} and {maximum}")
            return result

        def number(name: str, default: float, minimum: float, maximum: float) -> float:
            try:
                result = float(env.get(name, str(default)))
            except ValueError as exc:
                raise ValueError(f"{name} must be a number") from exc
            if not minimum <= result <= maximum:
                raise ValueError(f"{name} must be between {minimum} and {maximum}")
            return result

        settings = cls(
            database_url=database_url,
            admin_username=admin_username,
            admin_password=admin_password,
            socks_host=env.get("SOCKS_HOST", "127.0.0.1"),
            socks_port=integer("SOCKS_PORT", 4041, 1, 65535),
            router_host=env.get("ROUTER_HOST", "0.0.0.0"),
            router_port=integer("ROUTER_PORT", 4040, 1, 65535),
            health_host=env.get("HEALTH_HOST", "0.0.0.0"),
            health_port=integer("HEALTH_PORT", 8080, 1, 65535),
            mtproto_port=integer("MTPROTO_PORT", 4042, 1, 65535),
            mtproto_stats_port=integer("MTPROTO_STATS_PORT", 8888, 1, 65535),
            mtproto_workers=integer("MTPROTO_WORKERS", 1, 1, 8),
            mtproto_secret=mtproto_secret,
            mtproto_proxy_tag=mtproto_proxy_tag,
            max_connections=integer("MAX_CONNECTIONS", 200, 1, 10000),
            max_connections_per_user=integer("MAX_CONNECTIONS_PER_USER", 20, 1, 1000),
            connect_timeout=number("CONNECT_TIMEOUT_SECONDS", 10.0, 1.0, 120.0),
            auth_timeout=number("AUTH_TIMEOUT_SECONDS", 10.0, 1.0, 60.0),
            allowed_ports=parse_allowed_ports(env.get("ALLOWED_PORTS")),
        )

        listener_ports = [settings.router_port, settings.socks_port, settings.health_port]
        if settings.mtproto_secret:
            listener_ports.extend([settings.mtproto_port, settings.mtproto_stats_port])
        if len(listener_ports) != len(set(listener_ports)):
            raise ValueError("Router, SOCKS5, MTProto, stats, and health ports must be different")

        return settings
