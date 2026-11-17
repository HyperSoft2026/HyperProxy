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


async def run() -> None:
    configure_logging()
    logger = logging.getLogger("hyperproxy")
    settings = Settings.from_env()

    logger.info("Starting HyperProxy v%s", __version__)
    pool = await asyncpg.create_pool(
        dsn=settings.database_url,
        min_size=1,
        max_size=15,
        timeout=settings.connect_timeout,
        command_timeout=15,
    )
    database = Database(pool)
    await database.initialize(
        settings.admin_username,
        settings.admin_password,
        min(settings.max_connections_per_user, 20),
    )

    socks = Socks5Server(settings, database)
    router = ProtocolRouter(
        settings.router_host,
        settings.router_port,
        settings.socks_host,
        settings.socks_port,
        "127.0.0.1",
        settings.mtproto_port,
        settings.mtproto_secret is not None,
        settings.max_connections,
    )
    mtproto = MtprotoProcess(settings)
    health = HealthServer(database)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass

    socks_server = None
    router_server = None
    health_server = None
    try:
        await mtproto.start()
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
        if settings.mtproto_secret:
            logger.info("MTProto is enabled on internal port %d", settings.mtproto_port)

        await stop.wait()
    finally:
        for server in (router_server, socks_server, health_server):
            if server is not None:
                server.close()
        await asyncio.gather(
            *(
                server.wait_closed()
                for server in (router_server, socks_server, health_server)
                if server is not None
            )
        )
        await mtproto.stop()
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
