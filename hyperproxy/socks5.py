"""Authenticated SOCKS5 CONNECT server (RFC 1928 / RFC 1929)."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import time
from collections import defaultdict
from typing import Any

from .config import Settings
from .database import Database
from .security import is_public_ip

logger = logging.getLogger("hyperproxy.socks5")

SOCKS_VERSION = 5
METHOD_USERNAME_PASSWORD = 2
AUTH_VERSION = 1
CMD_CONNECT = 1


class Socks5Server:
    def __init__(self, settings: Settings, database: Database) -> None:
        self.settings = settings
        self.database = database
        self._active_total = 0
        self._active_by_user: dict[str, int] = defaultdict(int)
        self._capacity_lock = asyncio.Lock()
        # scrypt is intentionally expensive; cap simultaneous verifications to
        # avoid memory/CPU exhaustion during password-guessing attempts.
        self._auth_semaphore = asyncio.Semaphore(8)

    async def start(self) -> asyncio.AbstractServer:
        return await asyncio.start_server(
            self.handle_client,
            self.settings.socks_host,
            self.settings.socks_port,
            limit=65536,
            reuse_address=True,
        )

    async def _read(self, reader: asyncio.StreamReader, count: int) -> bytes:
        return await asyncio.wait_for(reader.readexactly(count), self.settings.auth_timeout)

    async def _reply(self, writer: asyncio.StreamWriter, code: int) -> None:
        # IPv4 0.0.0.0:0 is a valid placeholder BND.ADDR/BND.PORT.
        writer.write(bytes((SOCKS_VERSION, code, 0, 1, 0, 0, 0, 0, 0, 0)))
        await writer.drain()

    async def _reserve(self, username: str, user_limit: int) -> bool:
        async with self._capacity_lock:
            if self._active_total >= self.settings.max_connections:
                return False
            if self._active_by_user[username] >= min(user_limit, self.settings.max_connections_per_user):
                return False
            self._active_total += 1
            self._active_by_user[username] += 1
            return True

    async def _release(self, username: str) -> None:
        async with self._capacity_lock:
            self._active_total = max(0, self._active_total - 1)
            self._active_by_user[username] = max(0, self._active_by_user[username] - 1)
            if self._active_by_user[username] == 0:
                self._active_by_user.pop(username, None)

    async def _read_destination(self, reader: asyncio.StreamReader) -> tuple[str, int]:
        version, command, reserved, address_type = await self._read(reader, 4)
        if version != SOCKS_VERSION or reserved != 0:
            raise ValueError("Malformed SOCKS5 request")
        if command != CMD_CONNECT:
            raise NotImplementedError("Only CONNECT is supported")

        if address_type == 1:
            host = socket.inet_ntop(socket.AF_INET, await self._read(reader, 4))
        elif address_type == 4:
            host = socket.inet_ntop(socket.AF_INET6, await self._read(reader, 16))
        elif address_type == 3:
            length = (await self._read(reader, 1))[0]
            if length == 0:
                raise ValueError("Empty destination hostname")
            raw_host = await self._read(reader, length)
            try:
                host = raw_host.decode("ascii").rstrip(".")
            except UnicodeDecodeError as exc:
                raise ValueError("Destination hostname must use IDNA encoding") from exc
            if not host or len(host) > 253 or any(ch.isspace() for ch in host):
                raise ValueError("Invalid destination hostname")
        else:
            raise ValueError("Unsupported address type")

        port = int.from_bytes(await self._read(reader, 2), "big")
        return host, port

    async def _resolve_public(self, host: str, port: int) -> list[tuple[Any, ...]]:
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None

        loop = asyncio.get_running_loop()
        if literal is not None:
            if not is_public_ip(str(literal)):
                raise PermissionError("Non-public destination address")
            family = socket.AF_INET6 if literal.version == 6 else socket.AF_INET
            return await loop.getaddrinfo(host, port, family=family, type=socket.SOCK_STREAM)

        try:
            records = await asyncio.wait_for(
                loop.getaddrinfo(host, port, type=socket.SOCK_STREAM),
                self.settings.connect_timeout,
            )
        except (OSError, asyncio.TimeoutError) as exc:
            raise OSError("Destination DNS lookup failed") from exc

        if not records:
            raise OSError("Destination has no address records")
        # Reject mixed public/private DNS answers to reduce DNS-rebinding/SSRF risk.
        if any(not is_public_ip(record[4][0]) for record in records):
            raise PermissionError("Destination resolved to a non-public address")
        return records

    async def _connect_upstream(self, records: list[tuple[Any, ...]]) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        loop = asyncio.get_running_loop()
        last_error: OSError | None = None
        for family, socktype, protocol, _canonical_name, sockaddr in records:
            upstream_socket = socket.socket(family, socktype, protocol)
            upstream_socket.setblocking(False)
            try:
                await asyncio.wait_for(
                    loop.sock_connect(upstream_socket, sockaddr),
                    self.settings.connect_timeout,
                )
                return await asyncio.open_connection(sock=upstream_socket)
            except (OSError, asyncio.TimeoutError) as exc:
                last_error = exc if isinstance(exc, OSError) else OSError("Connection timed out")
                upstream_socket.close()
        raise last_error or OSError("Could not connect to destination")

    async def _relay(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
    ) -> tuple[int, int]:
        counters = {"up": 0, "down": 0}

        async def pump(source: asyncio.StreamReader, destination: asyncio.StreamWriter, direction: str) -> None:
            while True:
                data = await source.read(65536)
                if not data:
                    try:
                        destination.write_eof()
                        await destination.drain()
                    except (AttributeError, OSError, RuntimeError):
                        pass
                    return
                counters[direction] += len(data)
                destination.write(data)
                await destination.drain()

        tasks = {
            asyncio.create_task(pump(client_reader, upstream_writer, "up")),
            asyncio.create_task(pump(upstream_reader, client_writer, "down")),
        }
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*done, *pending, return_exceptions=True)
        return counters["up"], counters["down"]

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        started = time.monotonic()
        username: str | None = None
        reserved = False
        upstream_writer: asyncio.StreamWriter | None = None
        outcome = "protocol_error"
        bytes_up = 0
        bytes_down = 0

        try:
            version, method_count = await self._read(reader, 2)
            if version != SOCKS_VERSION or method_count == 0:
                writer.write(b"\x05\xff")
                await writer.drain()
                return
            methods = await self._read(reader, method_count)
            if METHOD_USERNAME_PASSWORD not in methods:
                writer.write(b"\x05\xff")
                await writer.drain()
                outcome = "auth_method_rejected"
                return

            writer.write(b"\x05\x02")
            await writer.drain()

            auth_version, username_length = await self._read(reader, 2)
            if auth_version != AUTH_VERSION or username_length == 0:
                writer.write(b"\x01\x01")
                await writer.drain()
                outcome = "auth_failed"
                return
            raw_username = await self._read(reader, username_length)
            password_length = (await self._read(reader, 1))[0]
            if password_length == 0:
                writer.write(b"\x01\x01")
                await writer.drain()
                outcome = "auth_failed"
                return
            raw_password = await self._read(reader, password_length)
            try:
                username = raw_username.decode("utf-8")
                password = raw_password.decode("utf-8")
            except UnicodeDecodeError:
                writer.write(b"\x01\x01")
                await writer.drain()
                outcome = "auth_failed"
                return
            if len(username) > 64 or len(password) > 128:
                writer.write(b"\x01\x01")
                await writer.drain()
                outcome = "auth_failed"
                return

            async with self._auth_semaphore:
                user = await self.database.authenticate(username, password)
            if user is None:
                writer.write(b"\x01\x01")
                await writer.drain()
                outcome = "auth_failed"
                return
            if not await self._reserve(username, int(user["max_connections"])):
                writer.write(b"\x01\x01")
                await writer.drain()
                outcome = "connection_limit_rejected"
                return
            reserved = True
            writer.write(b"\x01\x00")
            await writer.drain()

            try:
                host, port = await self._read_destination(reader)
            except NotImplementedError:
                await self._reply(writer, 7)  # Command not supported
                outcome = "command_rejected"
                return
            except (ValueError, asyncio.IncompleteReadError):
                await self._reply(writer, 8)  # Address type / malformed request
                outcome = "request_rejected"
                return

            if port not in self.settings.allowed_ports:
                await self._reply(writer, 2)  # Connection not allowed by ruleset
                outcome = "destination_port_rejected"
                return

            try:
                records = await self._resolve_public(host, port)
                upstream_reader, upstream_writer = await self._connect_upstream(records)
            except PermissionError:
                await self._reply(writer, 2)
                outcome = "destination_address_rejected"
                return
            except (OSError, asyncio.TimeoutError):
                await self._reply(writer, 5)  # Connection refused / failed
                outcome = "upstream_connection_failed"
                return

            await self._reply(writer, 0)
            outcome = "connected"
            bytes_up, bytes_down = await self._relay(reader, writer, upstream_reader, upstream_writer)
        except asyncio.TimeoutError:
            outcome = "handshake_timeout"
        except asyncio.IncompleteReadError:
            outcome = "client_disconnected"
        except (ConnectionError, OSError):
            outcome = "connection_error"
        except Exception:
            outcome = "internal_error"
            logger.exception("Unexpected SOCKS5 handler error")
        finally:
            if upstream_writer is not None:
                upstream_writer.close()
                try:
                    await upstream_writer.wait_closed()
                except (ConnectionError, OSError):
                    pass
            if reserved and username is not None:
                await self._release(username)
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            duration_ms = int((time.monotonic() - started) * 1000)
            if username is not None:
                await self.database.record_event(username, outcome, bytes_up, bytes_down, duration_ms)
            logger.info("SOCKS5 session ended: outcome=%s duration_ms=%d", outcome, duration_ms)
