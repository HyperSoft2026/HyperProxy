import unittest

from hyperproxy.security import (
    DEFAULT_TELEGRAM_CIDRS,
    hash_password,
    is_allowed_telegram_ip,
    is_public_ip,
    parse_allowed_ports,
    parse_telegram_networks,
    verify_password,
)


class PasswordTests(unittest.TestCase):
    def test_password_hash_verifies(self):
        salt, digest = hash_password("a-long-test-password")
        self.assertTrue(verify_password("a-long-test-password", salt, digest))
        self.assertFalse(verify_password("wrong-password", salt, digest))

    def test_each_hash_uses_a_new_salt(self):
        salt_a, digest_a = hash_password("same-password")
        salt_b, digest_b = hash_password("same-password")
        self.assertNotEqual(salt_a, salt_b)
        self.assertNotEqual(digest_a, digest_b)


class DestinationPolicyTests(unittest.TestCase):
    def test_public_and_private_addresses(self):
        self.assertTrue(is_public_ip("1.1.1.1"))
        self.assertFalse(is_public_ip("127.0.0.1"))
        self.assertFalse(is_public_ip("10.0.0.1"))
        self.assertFalse(is_public_ip("169.254.169.254"))
        self.assertFalse(is_public_ip("::1"))
        self.assertFalse(is_public_ip("not-an-ip"))

    def test_telegram_only_destination_allowlist(self):
        networks = parse_telegram_networks()
        self.assertEqual(len(networks), len(DEFAULT_TELEGRAM_CIDRS))
        self.assertTrue(is_allowed_telegram_ip("149.154.175.53", networks))
        self.assertTrue(is_allowed_telegram_ip("91.108.56.130", networks))
        self.assertTrue(is_allowed_telegram_ip("2001:b28:f23d:f001::a", networks))
        self.assertFalse(is_allowed_telegram_ip("1.1.1.1", networks))
        self.assertFalse(is_allowed_telegram_ip("127.0.0.1", networks))
        self.assertFalse(is_allowed_telegram_ip("169.254.169.254", networks))

    def test_custom_telegram_networks_are_parsed_strictly(self):
        networks = parse_telegram_networks("149.154.160.0/20,91.108.4.0/22")
        self.assertEqual(len(networks), 2)
        with self.assertRaises(ValueError):
            parse_telegram_networks("not-a-network")
        with self.assertRaises(ValueError):
            parse_telegram_networks([])

    def test_default_allowed_ports(self):
        self.assertEqual(parse_allowed_ports(None), frozenset({80, 443, 5222}))

    def test_custom_allowed_ports(self):
        self.assertEqual(parse_allowed_ports("443, 80,443"), frozenset({80, 443}))

    def test_invalid_ports_are_rejected(self):
        with self.assertRaises(ValueError):
            parse_allowed_ports("443,70000")
        with self.assertRaises(ValueError):
            parse_allowed_ports("not-a-port")


if __name__ == "__main__":
    unittest.main()
