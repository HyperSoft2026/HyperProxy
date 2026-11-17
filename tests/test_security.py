import unittest

from hyperproxy.security import hash_password, is_public_ip, parse_allowed_ports, verify_password


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
