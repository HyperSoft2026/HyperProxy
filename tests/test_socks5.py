import asyncio
import unittest

from hyperproxy.config import Settings
from hyperproxy.socks5 import Socks5Server
from hyperproxy.security import parse_telegram_networks


class FakeDatabase:
    async def authenticate(self, username, password):
        if username == "test-user" and password == "test-password":
            return {"username": username, "max_connections": 2, "role": "user"}
        if username == "test-admin" and password == "unused-test-password":
            return {"username": username, "max_connections": 2, "role": "admin"}
        return None

    async def record_event(self, *args, **kwargs):
        return None


class Socks5ProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        settings = Settings(
            database_url="postgresql://unused",
            admin_username="test-admin",
            admin_password="unused-test-password",
            socks_host="127.0.0.1",
            socks_port=0,
            max_connections=5,
            max_connections_per_user=2,
            allowed_ports=frozenset({443}),
            telegram_allowed_networks=parse_telegram_networks(),
        )
        self.proxy = Socks5Server(settings, FakeDatabase())
        self.server = await self.proxy.start()
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()

    async def connect_and_authenticate(self, username="test-user", password="test-password"):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(b"\x05\x01\x02")
        await writer.drain()
        self.assertEqual(await reader.readexactly(2), b"\x05\x02")

        username_bytes = username.encode()
        password_bytes = password.encode()
        writer.write(bytes((1, len(username_bytes))) + username_bytes + bytes((len(password_bytes),)) + password_bytes)
        await writer.drain()
        return reader, writer

    async def test_authenticated_private_destination_is_rejected(self):
        reader, writer = await self.connect_and_authenticate()
        self.assertEqual(await reader.readexactly(2), b"\x01\x00")

        # SOCKS5 CONNECT to 127.0.0.1:443 must be denied by destination policy.
        writer.write(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x01\xbb")
        await writer.drain()
        response = await reader.readexactly(10)
        self.assertEqual(response[0:2], b"\x05\x02")
        writer.close()
        await writer.wait_closed()

    async def test_public_non_telegram_destination_is_rejected(self):
        reader, writer = await self.connect_and_authenticate()
        self.assertEqual(await reader.readexactly(2), b"\x01\x00")

        # A public IP is denied unless it belongs to Telegram's CIDR allowlist.
        writer.write(b"\x05\x01\x00\x01\x01\x01\x01\x01\x01\xbb")
        await writer.drain()
        response = await asyncio.wait_for(reader.readexactly(10), timeout=2)
        self.assertEqual(response[0:2], b"\x05\x02")
        writer.close()
        await writer.wait_closed()

    async def test_administrator_account_is_rejected_by_public_socks5(self):
        reader, writer = await self.connect_and_authenticate(
            username="test-admin",
            password="unused-test-password",
        )
        self.assertEqual(await reader.readexactly(2), b"\\x01\\x01")
        writer.close()
        await writer.wait_closed()

    async def test_bad_password_is_rejected(self):
        reader, writer = await self.connect_and_authenticate(password="incorrect-password")
        self.assertEqual(await reader.readexactly(2), b"\x01\x01")
        writer.close()
        await writer.wait_closed()


if __name__ == "__main__":
    unittest.main()
