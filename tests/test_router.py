import asyncio
import unittest

from hyperproxy.router import ProtocolRouter


class ProtocolRouterTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.socks_server = await asyncio.start_server(
            self._socks_backend,
            "127.0.0.1",
            0,
        )
        self.mtproto_server = await asyncio.start_server(
            self._mtproto_backend,
            "127.0.0.1",
            0,
        )
        self.socks_port = self.socks_server.sockets[0].getsockname()[1]
        self.mtproto_port = self.mtproto_server.sockets[0].getsockname()[1]
        self.router = ProtocolRouter(
            "127.0.0.1",
            0,
            "127.0.0.1",
            self.socks_port,
            "127.0.0.1",
            self.mtproto_port,
            True,
        )
        self.router_server = await self.router.start()
        self.router_port = self.router_server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.router_server.close()
        self.socks_server.close()
        self.mtproto_server.close()
        await asyncio.gather(
            self.router_server.wait_closed(),
            self.socks_server.wait_closed(),
            self.mtproto_server.wait_closed(),
        )

    @staticmethod
    async def _reply(reader, writer, marker):
        try:
            data = await reader.readexactly(3)
            writer.write(marker + data)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async def _socks_backend(self, reader, writer):
        await self._reply(reader, writer, b"S")

    async def _mtproto_backend(self, reader, writer):
        await self._reply(reader, writer, b"M")

    async def test_authenticated_socks5_greeting_routes_to_socks_backend(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.router_port)
        writer.write(b"\x05\x01\x02")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(4), timeout=2), b"S\x05\x01\x02")
        writer.close()
        await writer.wait_closed()

    async def test_obfuscated_handshake_routes_to_mtproto_backend(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.router_port)
        writer.write(b"\x11\x22\x33")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(4), timeout=2), b"M\x11\x22\x33")
        writer.close()
        await writer.wait_closed()


if __name__ == "__main__":
    unittest.main()
