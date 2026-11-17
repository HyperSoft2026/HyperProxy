"""Multiplex SOCKS5 and MTProto over one Clever Cloud TCP redirection."""

from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger("hyperproxy.router")


class ProtocolRouter:
    """Route authenticated SOCKS5 greetings to SOCKS5; all other traffic to MTProxy."""

    def __init__(
        self,
        host: str,
        port: int,
        socks_host: str,
        socks_port: int,
        mtproto_host: str,
        mtproto_port: int,
        mtproto_enabled: bool,
    ) -> None:
        self.host = host
        self.port = port
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.mtproto_host = mtproto_host
        self.mtproto_port = mtproto_port
        self.mtproto_enabled = mtproto_enabled

    async def start(self) -> asyncio.AbstractServer:
        return await asyncio.start_server(
            self.handle,
            self.host,
            self.port,
            limit=16384,
            reuse_address=True,
        )

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        prefix = bytearray()
        use_socks = not self.mtproto_enabled

        if self.mtproto_enabled:
            try:
                first = await asyncio.wait_for(reader.readexactly(1), timeout=5)
                prefix.extend(first)
                if first == b"\x05":
                    count_byte = await asyncio.wait_for(reader.readexactly(1), timeout=3)
                    prefix.extend(count_byte)
                    method_count = count_byte[0]
                    # HyperProxy requires SOCKS5 username/password authentication (method 0x02).
                    # MTProto's obfuscated handshake is otherwise forwarded unchanged.
                    if 1 <= method_count <= 16:
                        methods = await asyncio.wait_for(
                            reader.readexactly(method_count),
                            timeout=3,
                        )
                        prefix.extend(methods)
                        use_socks = 0x02 in methods
            except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, OSError):
                    pass
                return

        if use_socks:
            backend_host, backend_port = self.socks_host, self.socks_port
            protocol_name = "SOCKS5"
        else:
            backend_host, backend_port = self.mtproto_host, self.mtproto_port
            protocol_name = "MTProto"

        backend_writer: asyncio.StreamWriter | None = None
        try:
            backend_reader, backend_writer = await asyncio.open_connection(
                backend_host,
                backend_port,
            )
            if prefix:
                backend_writer.write(prefix)
                await backend_writer.drain()
            logger.debug("Routed incoming TCP connection to %s", protocol_name)
            await asyncio.gather(
                self._pipe(reader, backend_writer),
                self._pipe(backend_reader, writer),
            )
        except (ConnectionError, OSError, asyncio.TimeoutError):
            logger.debug("Could not establish %s backend connection", protocol_name, exc_info=True)
        finally:
            if backend_writer is not None:
                backend_writer.close()
                try:
                    await backend_writer.wait_closed()
                except (ConnectionError, OSError):
                    pass
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    @staticmethod
    async def _pipe(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        except (ConnectionError, OSError, asyncio.CancelledError):
            if isinstance(asyncio.current_task(), asyncio.Task) and asyncio.current_task().cancelled():
                raise
        finally:
            try:
                if writer.can_write_eof():
                    writer.write_eof()
                    await writer.drain()
            except (ConnectionError, OSError, RuntimeError):
                pass
