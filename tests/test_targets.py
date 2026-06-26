import unittest

from lanscope.targets import expand_targets


class ExpandTargetsTests(unittest.TestCase):
    def test_single_ip(self) -> None:
        self.assertEqual(expand_targets(["127.0.0.1"]), ["127.0.0.1"])

    def test_cidr(self) -> None:
        self.assertEqual(expand_targets(["192.0.2.0/30"]), ["192.0.2.1", "192.0.2.2"])

    def test_limit(self) -> None:
        with self.assertRaises(ValueError):
            expand_targets(["192.0.2.0/29"], max_hosts=2)


if __name__ == "__main__":
    unittest.main()
