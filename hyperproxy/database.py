"""PostgreSQL storage for proxy accounts and minimal connection metadata."""

from __future__ import annotations

import logging
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    import asyncpg

from .security import hash_password, verify_password

logger = logging.getLogger("hyperproxy.database")

SCHEMA = """
CREATE TABLE IF NOT EXISTS proxy_users (
    username TEXT PRIMARY KEY,
    password_salt BYTEA NOT NULL,
    password_hash BYTEA NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    max_connections INTEGER NOT NULL DEFAULT 10 CHECK (max_connections BETWEEN 1 AND 1000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS proxy_connection_events (
    id BIGSERIAL PRIMARY KEY,
    username TEXT,
    outcome TEXT NOT NULL,
    bytes_up BIGINT NOT NULL DEFAULT 0,
    bytes_down BIGINT NOT NULL DEFAULT 0,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_proxy_events_created_at
    ON proxy_connection_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_proxy_events_username_created_at
    ON proxy_connection_events (username, created_at DESC);
"""


class Database:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self.pool = pool

    async def initialize(
        self,
        admin_username: str,
        admin_password: str,
        admin_limit: int,
        public_username: str | None = None,
        public_password: str | None = None,
        public_limit: int = 10,
    ) -> None:
        async with self.pool.acquire() as connection:
            await connection.execute(SCHEMA)
            salt, digest = hash_password(admin_password)
            await connection.execute(
                """
                INSERT INTO proxy_users
                    (username, password_salt, password_hash, role, enabled, max_connections)
                VALUES ($1, $2, $3, 'admin', TRUE, $4)
                ON CONFLICT (username) DO UPDATE SET
                    password_salt = EXCLUDED.password_salt,
                    password_hash = EXCLUDED.password_hash,
                    role = 'admin',
                    enabled = TRUE,
                    max_connections = EXCLUDED.max_connections,
                    updated_at = NOW()
                """,
                admin_username,
                salt,
                digest,
                admin_limit,
            )

            # Public proxy users are separate from the private bootstrap administrator.
            # Keep only the configured public account enabled; never delete existing rows.
            if public_username and public_password:
                await connection.execute(
                    "UPDATE proxy_users SET enabled = FALSE WHERE role = 'user' AND username <> $1",
                    public_username,
                )
                public_salt, public_digest = hash_password(public_password)
                await connection.execute(
                    """
                    INSERT INTO proxy_users
                        (username, password_salt, password_hash, role, enabled, max_connections)
                    VALUES ($1, $2, $3, 'user', TRUE, $4)
                    ON CONFLICT (username) DO UPDATE SET
                        password_salt = EXCLUDED.password_salt,
                        password_hash = EXCLUDED.password_hash,
                        role = 'user',
                        enabled = TRUE,
                        max_connections = EXCLUDED.max_connections,
                        updated_at = NOW()
                    """,
                    public_username,
                    public_salt,
                    public_digest,
                    public_limit,
                )
            else:
                await connection.execute(
                    "UPDATE proxy_users SET enabled = FALSE WHERE role = 'user'"
                )

    async def authenticate(self, username: str, password: str) -> dict[str, Any] | None:
        async with self.pool.acquire() as connection:
            row = await connection.fetchrow(
                """
                SELECT username, password_salt, password_hash, role, enabled, max_connections
                FROM proxy_users WHERE username = $1
                """,
                username,
            )
        if row is None or not row["enabled"]:
            return None
        if not verify_password(password, bytes(row["password_salt"]), bytes(row["password_hash"])):
            return None
        return {
            "username": row["username"],
            "role": row["role"],
            "max_connections": int(row["max_connections"]),
        }

    async def record_event(
        self,
        username: str | None,
        outcome: str,
        bytes_up: int = 0,
        bytes_down: int = 0,
        duration_ms: int = 0,
    ) -> None:
        try:
            async with self.pool.acquire() as connection:
                await connection.execute(
                    """
                    INSERT INTO proxy_connection_events
                        (username, outcome, bytes_up, bytes_down, duration_ms)
                    VALUES ($1, $2, $3, $4, $5)
                    """,
                    username,
                    outcome[:40],
                    max(0, bytes_up),
                    max(0, bytes_down),
                    max(0, duration_ms),
                )
        except Exception:
            logger.exception("Could not write connection event")

    async def is_ready(self) -> bool:
        try:
            async with self.pool.acquire() as connection:
                await connection.fetchval("SELECT 1")
            return True
        except Exception:
            logger.warning("PostgreSQL readiness check failed", exc_info=True)
            return False
