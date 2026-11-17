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
    ihซ– x zา่ซ*^ฎ่ว+ถุง