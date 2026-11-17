import unittest
from unittest.mock import AsyncMock, patch

import asyncpg

from hyperproxy.__main__ import create_database_pool
from hyperproxy.config import Settings


BASE_ENV = {
    "DATABASE_URL": "postgresql://unused",
    "PROXY_ADMIN_USERNAME": "test-admin",
    "PROXY_ADMIN_PASSWORD": "a-long-test-password",
}


class DatabasePoolStartupTests(unittest.IsolatedAsyncioTestCase):
    async def test_retries_temporary_connection_limit_error(self):
        settings = Settings.from_env(BASE_ENV)
        expected_pool = object()

        with (
            patch(
                "hyperproxy.__main__.asyncpg.create_pool",
                new_callable=AsyncMock,
            ) as create_pool,
            patch(
                "hyperproxy.__main__.asyncio.sleep",
                new_callable=AsyncMock,
            ) as sleep,
        ):
            create_pool.side_effect = [
                asyncpg.exceptions.TooManyConnectionsError("connection limit"),
                expected_pool,
            ]

            pool = await create_database_pool(settings)

        self.assertIs(pool, expected_pool)
        self.assertEqual(create_pool.await_count, 2)
        sleep.assert_awaited_once_with(2)
        kwargs = create_pool.await_args.kwargs
        self.assertEqual(kwargs["min_size"], 1)
        self.assertEqual(kwargs["max_size"], 3)
        self.assertEqual(kwargs["max_inactive_connection_lifetime"], 60)

    async def test_does_not_retry_unrelated_connection_errors(self):
        settings = Settings.from_env(BASE_ENV)

        with patch(
            "hyperproxy.__main__.asyncpg.create_pool",
            new_callable=AsyncMock,
        ) as create_pool:
            create_pool.side_effect = OSError("database unavailable")

            with self.assertRaisesRegex(OSError, "database unavailable"):
                await create_database_pool(settings)

        self.assertEqual(create_pool.await_count, 1)

    async def test_stops_after_three_connection_limit_failures(self):
        settings = Settings.from_env(BASE_ENV)

        with (
            patch(
                "hyperproxy.__main__.asyncpg.create_pool",
                new_callable=AsyncMock,
            ) as create_pool,
            patch(
                "hyperproxy.__main__.asyncio.sleep",
                new_callable=AsyncMock,
            ) as sleep,
        ):
            create_pool.side_effect = asyncpg.exceptions.TooManyConnectionsError(
                "connection limit"
            )

            with self.assertRaises(asyncpg.exceptions.TooManyConnectionsError):
                await create_database_pool(settings)

        self.assertEqual(create_pool.await_count, 3)
        self.assertEqual(
            [call.args[0] for call in sleep.await_args_list],
            [2, 4],
        )


if __name__ == "__main__":
    unittest.main()
