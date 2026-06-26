import unittest

from lanscope.profiles import get_profile


class ScanProfileTests(unittest.TestCase):
    def test_full_profile_uses_all_ports_and_discovery(self) -> None:
        profile = get_profile("full")
        self.assertEqual(profile.ports, "full")
        self.assertTrue(profile.discover_hosts)
        self.assertGreaterEqual(profile.global_concurrency, profile.per_host_concurrency)


if __name__ == "__main__":
    unittest.main()
