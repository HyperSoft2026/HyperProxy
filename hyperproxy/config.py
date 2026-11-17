"""Environment-based configuration for HyperProxy."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping

from .security import parse_allowed_ports


@dataclass(frozen=True, slots=True)
class Settings:
    database_url: str
    admin_username: str
    admin_password: str
    socks_host: str = "0.0.0.0"
    socks_port: int = 4040
    health_host: str = "0.0.0.0"
    health_port: int = 8080
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

        if not database_url:
            raise ValueError("Set DATABASE_URL or POSTGRESQL_ADDON_URI before starting HyperProxy")
        if not admin_username or len(admin_username) > 64:
            raise ValueError("PROXY_ADMIN_USERNAME must contain 1 to 64 characters")
        if len(admin_password) < 16:
            raise ValueError("PROXY_ADMIN_PASSWORD must be at least 16 characters")

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

        return cls(
            database_url=database_url,
            admin_username=admin_username,
            admin_password=admin_password,
            socks_host=env.get("SOCKS_HOST", "0.0.0.0"),
            socks_port=integer("SOCKS_PORT", 4040, 1, 65535),
            health_host=env.get("HEALTH_HOST", "0.0.0.0"),
            health_port=integer("HEALTH_PORT", 8080, 1, 65535),
            max_connections=integer("MAX_CONNECTIONS", 200, 1, 10000),
            max_connections_per_user=integer("MAX_CONNECTIONS_PER_USER", 20, 1, 1000),
            connect_timeout=number("CONNECT_TIMEOUT_SECONDS", 10.0, 1.0, 120.0),
            auth_timeout=number("AUTH_TIMEOUT_SECONDS", 10.0, 1.0, 60.0),
            allowed_ports=parse_allowed_ports(env.get("ALLOWED_PORTS")),
        )
