"""Minimal HTTP health endpoints required by Clever Cloud Docker runtime."""

from __future__ import annotations

import asyncio
import json
import logging

from .database import Database

logger = logging.getLogger("hyperproxy.health")


class HealthServer:
    def __init__(self, database: Database) -> None:
        self.database = database

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        status = 200
        payload: dict[str, str] = {"service": "HyperProxy", "status": "ok", "version": "1.0.0"}
        method = "GET"
        try:
            request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=3)
            if len(request) > 8192:
                raise ValueError("Request headers too large")
            first_line = request.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
            parts = first_line.split()
            if len(parts) < 2:
                status = 400
                payload = {"status": "bad_request"}
            else:
                method, path = parts[0].upper(), parts[1].split("?", 1)[0]
                if method not in {"GET", "HEAD"}:
                    status = 405
                    payload = {"status": "method_not_allowed"}
                elif path == "/ready":
                    ready = await self.database.is_ready()
                    status = 200 if ready else 503
                    payload = {"service": "HyperProxy", "status": "ready" if ready else "not_ready"}
                elif path in {"/", "/health", "/healthz"}:
                    pass
                else:
                    status = 404
                    payload = {"status": "not_found"}
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ValueError):
            status = 400
            payload = {"status": "bad_request"}
        except Exception:
            logger.exception("Health request failed")
            status = 500
            payload = {"status": "internal_error"}

        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        reason = {200: "OK", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed", 500: "Internal Server Error", 503: "Service Unavailable"}.get(status, "OK")
        headers = (
            f"HTTP/1.1 {status} {reason}\r\n"
            "Content-Type: application/json; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "Cache-Control: no-store\r\n\r\n"
        ).encode("ascii")
        writer.write(headers)
        if method != "HEAD":
            writer.write(body)
        try:
            await writer.drain()
        except (ConnectionError, OSError):
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
