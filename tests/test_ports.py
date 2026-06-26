import unittest

from lanscope.ports import parse_ports


class ParsePortsTests(unittest.TestCase):
    def test_named_set(self) -> None:
        ports = parse_ports("common")
        self.assertIn(80, ports)
        self.assertIn(443, ports)

    def test_list_and_range(self) -> None:
        self.assertEqual(parse_ports("22,80,8000-8002"), [22, 80, 8000, 8001, 8002])

    def test_rejects_invalid_port(self) -> None:
        with self.assertRaises(ValueError):
            parse_ports("0")

    def test_full_alias(self) -> None:
        ports = parse_ports("full")
        self.assertEqual(ports[0], 1)
        self.assertEqual(ports[-1], 65535)
        self.assertEqual(len(ports), 65535)


if __name__ == "__main__":
    unittest.main()
