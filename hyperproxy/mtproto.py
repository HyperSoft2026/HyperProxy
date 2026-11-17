"""Lifecycle management for Telegram's official MTProxy binary."""

from __future__ import annotations

import asyncio
import logging
import shutil
from pathlib import Path
from tempfile import gettempdir
from urllib.request import Request, urlopen

from .config import Settings

logger = logging.getLogger("hyperproxy.mtproto")

PROXY_SECRET_URL = "https://core.telegram.org/getProxySecret"
PROXY_CONFIG_URL = "https://core.telegram.org/getProxyConfig"
BINARY = "/usr/local/bin/mtproto-proxy"


def _download_file(url: str, destination: Path, minimum_size: int) -> None:
    request = Request(url, headers={"User-Agent": "HyperProxy/1.1"})
    with urlopen(request, timeout=20) as response:
        data = response.read(4 * 1024 * 1024 + 1)
    if len(data) < minimum_size or len(data) > 4 * 1024 * 1024:
        raise RuntimeError(f"Telegram returned an invalid configuration file: {url}")
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_bytes(data)
    temporary.chmod(0o600)
    temporary.replace(destination)


class MtprotoProcess:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.process: asyncio.subprocess.Process | None = None

    async def start(self) -> None:
        if not self.settings.mtproto_secret:
            logger.info("MTProto is disabled; SOCKS5 remains available")
            return

        if shutil.which(BINARY) is None:
            raise RuntimeError("MTProxy binary is missing from the container image")

        config_dir = Path(gettempdir()) / "hyperproxy-mtproto"
        config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        proxy_secret_file = config_dir / "proxy-secret"
        proxy_config_file = config_dir / "proxy-multi.conf"

        await asyncio.to_thread(
            _download_file,
            PROXY_SECRET_URL,
            proxy_secret_file,
            16,
        )
        await asyncio.to_thread(
            _download_file,
            PROXY_CONFIG_URL,
            proxy_config_file,
            100,
        )

        command = [
            BINARY,
            "-u",
            "hyperproxy",
            "-p",
            str(self.settings.mtproto_stats_port),
            "-H",
            str(self.settings.mtproto_port),
            "-S",
            self.settings.mtproto_secret,
        ]
        if self.settings.mtproto_proxy_tag:
            command.extend(["-P", self.settings.mtproto_proxy_tag])
        command.extend(
            [
                "--aes-pwd",
                str(proxy_secret_file),
                str(proxy_config_file),
                "-M",
                str(self.settings.mtproto_workers),
            ]
        )

        self.process = await asyncio.create_subprocess_exec(*command)
        await asyncio.sleep(0.75)
        if self.process.returncode is not None:
            return_code = self.process.returncode
            self.process = None
            raise RuntimeError(f"MTProxy exited during startup with status {return_code}")

        logger.info(
            "MTProto listening on 127.0.0.1:%d; promotion tag %s",
            self.settings.mtproto_port,
            "configured" if self.settings.mtproto_proxy_tag else "not configured yet",
        )

    async def stop(self) -> None:
        process = self.process
        if process is None or process.returncode is not None:
            return
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=10)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
        self.process = None
