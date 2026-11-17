import asyncio
import socket
import unittest
from types import SimpleNamespace

from hyperproxy.mtproto import wait_for_listener


class MtprotoListenerTests(unittest.IsolatedAsyncioTestCase):
    async def test_waits_until_client_listener_accepts_connections(self):
        async def close_connection(reader, writer):
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(close_connection, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        process = SimpleNamespace(returncode=None)
        try:
            await wait_for_listener("127.0.0.1", port, process, timeout=0.5)
        finally:
            server.close()
            await server.wait_closed()

    async def test_fails_when_process_exits_before_listener_is_ready(self):
        process = SimpleNamespace(returncode=1)
        with self.assertRaisesRegex(RuntimeError, "exited before opening"):
            await wait_for_listener("127.0.0.1", 1, process, timeout=0.1)

    async def test_fails_when_listener_never_opens(self):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()

        process = SimpleNamespace(returncode=None)
        with self.assertRaisesRegex(RuntimeError, "did not open client port"):
            await wait_for_listener("127.0.0.1", port, process, timeout=0.15)


if __name__ == "__main__":
    unittest.main()
