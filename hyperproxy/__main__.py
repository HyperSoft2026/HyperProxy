"""HyperProxy application entry point."""

from __future__ import annotations

import asyncio
import logging
import os
import signal

import asyncpg

from . import __version__
from .config import Settings
from .database import Database
from .health import HealthServer
from .mtproto import MtprotoProcess
from .router import ProtocolRouter
from .socks5 import Socks5Server


def configure_logging() -> None:
    level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


async def create_database_pool(settings: Settings) -> asyncpg.Pool:
    """Create a small PostgreSQL pool, retrying temporary connection-limit errors."""
    logger = logging.getLogger("hyperproxy")
    attempts = 3

    for attempt in range(1, attempts + 1):
        try:
            return await asyncpg.create_pool(
                dsn=settings.database_url,
                min_size=settings.database_pool_min_size,
                max_size=settings.database_pool_max_size,
                max_inactive_connection_lifetime=settings.database_pool_idle_seconds,
                timeout=settings.connect_timeout,
                command_timeout=15,
            )
        except asyncpg.exceptions.TooManyConnectionsError:
            if attempt == attempts:
                raise
            delay = 2**attempt
            logger.warning(
                "PostgreSQL connection limit reached; retrying pool creation in %d seconds (attempt %d/%d)",
                delay,
                attempt,
                attempts,
            )
            await asyncio.sleep(delay)

    raise RuntimeError("PostgreSQL pool creation ended unexpectedly")


async def run() -> None:
    configure_logging()
    logger = logging.getLogger("hyperproxy")
    settings = Settings.from_env()

    logger.info("Starting HyperProxy v%s", __version__)
    pool = await create_database_pool(settings)
    logger.info(
        "PostgreSQL pool configured: min=%d max=%d idle_timeout=%ds",
        settings.database_pool_min_size,
        settings.database_pool_max_size,
        settings.database_pool_idle_seconds,
    )

    database = Database(pool)
    mtproto = MtprotoProcess(settings)
    socks_server = None
    router_server = None
    health_server = None

    try:
        await database.initialize(
            settings.admin_username,
            settings.admin_password,
            min(settings.max_connections_per_user, 20),
        )

        socks = Socks5Server(settings, database)
        health = HealthServer(database)

        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, stop.set)
            except NotImplementedError:
                pass

        try:
            await mtproto.start()
        except Exception:
            # Keep the already-working SOCKS5 service available if Telegram's
            # config endpoints or the optional MTProxy process are unavailable.
            logger.exception("MTProto could not start; continuing with SOCKS5 only")

        router = ProtocolRouter(
            settings.router_host,
            settings.router_port,
            settings.socks_host,
            settings.socks_port,
            "127.0.0.1",
            settings.mtproto_port,
            mtproto.is_running,
            settings.max_connections,
        )
        socks_server = await socks.start()
        router_server = await router.start()
        health_server = await asyncio.start_server(
            health.handle,
            settings.health_host,
            settings.health_port,
            limit=16384,
            reuse_address=True,
        )

        logger.info("SOCKS5 backend listening on %s:%d", settings.socks_host, settings.socks_port)
        logger.info("TCP protocol router listening on %s:%d", settings.router_host, settings.router_port)
        logger.info("HTTP health listening on %s:%d", settings.health_host, settings.health_port)
        logger.info("Allowed SOCKS5 destination ports: %s", ",".join(map(str, sorted(settings.allowed_ports))))
        if mtproto.is_running:
            logger.info("MTProto is enabled on internal port %d", settings.mtproto_port)
        elif settings.mtproto_secret:
            logger.error("MTProto is configured but unavailable; SOCKS5 remains active")

        await stop.wait()
    finally:
        servers = (router_server, socks_server, health_server)
        for server in servers:
            if server is not None:
                server.close()
        await asyncio.gather(
            *(server.wait_closed() for server in servers if server is not None)
        )
        try:
            await mtproto.stop()
        finally:
            await pool.close()
        logger.info("HyperProxy stopped cleanly")


def main() -> None:
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
    except Exception:
        logging.getLogger("hyperproxy").exception("HyperProxy failed to start")
        raise


if __name__ == "__main__":
    main()
