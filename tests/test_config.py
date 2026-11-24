import unittest

from hyperproxy.config import Settings


BASE_ENV = {
    "DATABASE_URL": "postgresql://unused",
    "PROXY_ADMIN_USERNAME": "test-admin",
    "PROXY_ADMIN_PASSWORD": "a-long-test-password",
}


class MtprotoConfigTests(unittest.TestCase):
    def test_mtproto_is_optional_by_default(self):
        settings = Settings.from_env(BASE_ENV)
        self.assertIsNone(settings.mtproto_secret)
        self.assertIsNone(settings.mtproto_proxy_tag)
        self.assertEqual(settings.router_port, 4040)
        self.assertEqual(settings.socks_port, 4041)
        self.assertEqual(settings.mtproto_port, 4042)
        self.assertGreater(len(settings.telegram_allowed_networks), 0)
        self.assertIsNone(settings.public_username)
        self.assertIsNone(settings.public_password)

    def test_legacy_socks_listener_variables_keep_public_port(self):
        env = {**BASE_ENV, "SOCKS_HOST": "0.0.0.0", "SOCKS_PORT": "4040"}
        settings = Settings.from_env(env)
        self.assertEqual(settings.router_host, "0.0.0.0")
        self.assertEqual(settings.router_port, 4040)
        self.assertEqual(settings.socks_host, "127.0.0.1")
        self.assertEqual(settings.socks_port, 4041)

    def test_separate_public_proxy_account(self):
        env = {
            **BASE_ENV,
            "PROXY_PUBLIC_USERNAME": "telegram-users",
            "PROXY_PUBLIC_PASSWORD": "a-separate-public-password",
        }
        settings = Settings.from_env(env)
        self.assertEqual(settings.public_username, "telegram-users")
        self.assertEqual(settings.public_password, "a-separate-public-password")

    def test_public_account_requires_both_credentials(self):
        env = {**BASE_ENV, "PROXY_PUBLIC_USERNAME": "telegram-users"}
        with self.assertRaises(ValueError):
            Settings.from_env(env)

    def test_public_account_cannot_reuse_admin_credentials(self):
        env = {
            **BASE_ENV,
            "PROXY_PUBLIC_USERNAME": "test-admin",
            "PROXY_PUBLIC_PASSWORD": "a-separate-public-password",
        }
        with self.assertRaises(ValueError):
            Settings.from_env(env)
        env = {
            **BASE_ENV,
            "PROXY_PUBLIC_USERNAME": "telegram-users",
            "PROXY_PUBLIC_PASSWORD": BASE_ENV["PROXY_ADMIN_PASSWORD"],
        }
        with self.assertRaises(ValueError):
            Settings.from_env(env)

    def test_valid_mtproto_secret_and_tag(self):
        env = {
            **BASE_ENV,
            "MTPROTO_SECRET": "0123456789abcdef0123456789abcdef",
            "MTPROTO_PROXY_TAG": "abcdef0123456789abcdef0123456789",
        }
        settings = Settings.from_env(env)
        self.assertEqual(settings.mtproto_secret, env["MTPROTO_SECRET"])
        self.assertEqual(settings.mtproto_proxy_tag, env["MTPROTO_PROXY_TAG"])

    def test_invalid_mtproto_secret_is_rejected(self):
        env = {**BASE_ENV, "MTPROTO_SECRET": "not-a-secret"}
        with self.assertRaises(ValueError):
            Settings.from_env(env)

    def test_tag_requires_secret(self):
        env = {**BASE_ENV, "MTPROTO_PROXY_TAG": "abcdef0123456789abcdef0123456789"}
        with self.assertRaises(ValueError):
            Settings.from_env(env)

    def test_invalid_tag_is_rejected(self):
        env = {
            **BASE_ENV,
            "MTPROTO_SECRET": "0123456789abcdef0123456789abcdef",
            "MTPROTO_PROXY_TAG": "not-a-tag",
        }
        with self.assertRaises(ValueError):
            Settings.from_env(env)

    def test_database_pool_defaults_are_conservative(self):
        settings = Settings.from_env(BASE_ENV)
        self.assertEqual(settings.database_pool_min_size, 1)
        self.assertEqual(settings.database_pool_max_size, 3)
        self.assertEqual(settings.database_pool_idle_seconds, 60)

    def test_database_pool_can_be_configured(self):
        env = {
            **BASE_ENV,
            "DB_POOL_MIN_SIZE": "2",
            "DB_POOL_MAX_SIZE": "5",
            "DB_POOL_IDLE_SECONDS": "120",
        }
        settings = Settings.from_env(env)
        self.assertEqual(settings.database_pool_min_size, 2)
        self.assertEqual(settings.database_pool_max_size, 5)
        self.assertEqual(settings.database_pool_idle_seconds, 120)

    def test_database_pool_minimum_cannot_exceed_maximum(self):
        env = {**BASE_ENV, "DB_POOL_MIN_SIZE": "4", "DB_POOL_MAX_SIZE": "3"}
        with self.assertRaises(ValueError):
            Settings.from_env(env)

    def test_database_pool_idle_timeout_is_bounded(self):
        env = {**BASE_ENV, "DB_POOL_IDLE_SECONDS": "10"}
        with self.assertRaises(ValueError):
            Settings.from_env(env)


if __name__ == "__main__":
    unittest.main()
