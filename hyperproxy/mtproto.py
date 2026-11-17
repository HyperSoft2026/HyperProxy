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

async def wait_for_listener(
    host: str,
    port: int,
    process: asyncio.subprocess.Process,
    timeout: float = 10.0,
) -> None:
    """Wait until MTProxy accepts a local TCP connection on its client port."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    last_error: BaseException | None = None

    while True:
        if process.returncode is not None:
            raise RuntimeError(
                f"MTProxy exited before opening client port {port} "
                f"with status {process.returncode}"
            )

        remaining = deadline - loop.time()
        if remaining <= 0:
            raise RuntimeError(
                f"MTProxy stayed running but did not open client port {port} "
                f"within {timeout:g} seconds"
            ) from last_error

        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=min(0.5, remaining),
            )
            writer.close()
            await writer.wait_closed()
            return
        except (ConnectionError, OSError, asyncio.TimeoutError) as exc:
            last_error = exc
            await asyncio.sleep(min(0.1, max(0.0, deadline - loop.time())))


async def read_mtproxy_stats(
    host: str,
    port: int,
    timeout: float = 2.0,
) -> dict[str, str]:
    """Read the official MTProxy loopback /stats endpoint."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port),
        timeout=timeout,
    )
    try:
        writer.write(
            b"GET /stats HTTP/1.0\r\n"
            b"Host: localhost\r\n"
            b"Connection: close\r\n\r\n"
        )
        await writer.drain()
        response = await asyncio.wait_for(reader.read(65536), timeout=timeout)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass

    header, separator, body = response.partition(b"\r\n\r\n")
    if not separator or b" 200 " not in header.split(b"\r\n", 1)[0]:
        raise RuntimeError("MTProxy stats endpoint did not return HTTP 200")

    stats: dict[str, str] = {}
    for raw_line in body.decode("utf-8", errors="replace").splitlines():
        fields = raw_line.strip().replace("=", " ").split()
        if len(fields) >= 2:
            stats[fields[0]] = fields[1]
    return stats



PROXY_SECRET_URL = "https://core.telegram.org/getProxySecret"
PROXY_CONFIG_URL = "https://core.telegram.org/getProxyConfig"
BINARY = "/usr/local/bin/mtproto-proxy"


def _download_file(url: str, destination: Path, minimum_size: int) -> None:
    request = Request(url, headers={"User-Agent": "HyperProxy/1.1"})
    with urlopen(request, timeout=20) as response:
        data = response.read(4 * 1024 * 1024 + 1)
    if (
        len(data) < minimum_size
        or len(data) > 4 * 1024 * 1024
        or b"<html" in data[:512].lower()
        or b"<!doctype" in data[:512].lower()
    ):
        raise RuntimeError(f"Telegram returned an invalid configuration file: {url}")
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_bytes(data)
    temporary.chmod(0o600)
    temporary.replace(destination)


class MtprotoProcess:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.process: asyncio.subprocess.Process | None = None

    @property
    def is_running(self) -> bool:
        return self.process is not None and self.process.returncode is None

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
        try:
            await wait_for_listener(
                "127.0.0.1",
                self.settings.mtproto_port,
                self.process,
                timeout=10.0,
            )
        except Exception:
            process = self.process
            if process is not None and process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
            self.process = None
            raise

        logger.info(
            "MTProto client listener verified on 127.0.0.1:%d; promotion tag %s",
            self.settings.mtproto_port,
            "configured" if self.settings.mtproto_proxy_tag else "not configured",
        )
        try:
            stats = await read_mtproxy_stats(
                "127.0.0.1",
                self.settings.mtproto_stats_port,
            )
            ready = stats.get("ready_targets", "unknown")
            active = stats.get("active_targets", "unknown")
            clients = stats.get("total_special_connections", "unknown")
            logger.info(
                "MTProxy upstream stats: ready_targets=%s active_targets=%s inbound_connections=%s",
                ready,
                active,
                clients,
            )
            if ready.isdigit() and active.isdigit() and int(ready) > 0 and int(active) < int(ready):
                logger.warning(
                    "MTProxy has fewer active Telegram upstream targets than configured targets"
                )
        except (ConnectionError, OSError, asyncio.TimeoutError, RuntimeError) as exc:
            logger.warning("Could not read MTProxy loopback stats: %s", exc)

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
