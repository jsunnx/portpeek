# -*- coding: utf-8 -*-
from __future__ import annotations

import unittest

from portpeek.core import (
    PortEntry,
    _split_host_port,
    _WIN_TCP,
    _WIN_UDP,
    _SS_LINE,
    is_protected_process,
    entries_to_json,
)


class TestWindowsParse(unittest.TestCase):
    def test_tcp_line(self):
        line = "TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4"
        m = _WIN_TCP.match(line.strip())
        self.assertIsNotNone(m)
        self.assertEqual(m.group("proto").upper(), "TCP")
        self.assertEqual(m.group("local"), "0.0.0.0:80")
        self.assertEqual(m.group("state").upper(), "LISTENING")
        self.assertEqual(m.group("pid"), "4")
        hp = _split_host_port(m.group("local"))
        self.assertEqual(hp, ("0.0.0.0", 80))

    def test_udp_line_no_state(self):
        line = "UDP    0.0.0.0:443         *:*                                    20880"
        m = _WIN_UDP.match(line.strip())
        self.assertIsNotNone(m)
        self.assertIsNone(_WIN_TCP.match(line.strip()))
        self.assertEqual(m.group("pid"), "20880")
        hp = _split_host_port(m.group("local"))
        self.assertEqual(hp, ("0.0.0.0", 443))

    def test_ipv6_brackets(self):
        hp = _split_host_port("[::]:1900")
        self.assertEqual(hp, ("[::]", 1900))
        hp2 = _split_host_port("[2001:db8::1]:8080")
        self.assertEqual(hp2, ("[2001:db8::1]", 8080))

    def test_star_star_rejected(self):
        self.assertIsNone(_split_host_port("*:*"))

    def test_json_ascii_safe(self):
        e = PortEntry("UDP", "0.0.0.0", 443, 1, "LISTENING", process_name="微信")
        s = entries_to_json([e])
        self.assertNotIn("微", s)
        self.assertIn("\\u", s)

    def test_ss_udp_listen(self):
        line = (
            "udp   UNCONN 0      0      0.0.0.0:68          0.0.0.0:*    "
            'users:(("dhclient",pid=456,fd=6))'
        )
        m = _SS_LINE.match(line.strip())
        self.assertIsNotNone(m)
        self.assertEqual(m.group("netid").lower(), "udp")
        self.assertEqual(m.group("state").upper(), "UNCONN")


class TestProtected(unittest.TestCase):
    def test_system_pid(self):
        e = PortEntry("TCP", "0.0.0.0", 80, 4, "LISTENING", process_name="System")
        self.assertTrue(is_protected_process(e))

    def test_lsass(self):
        e = PortEntry("TCP", "0.0.0.0", 10496, 1648, "LISTENING", process_name="lsass")
        self.assertTrue(is_protected_process(e))

    def test_node_not_protected(self):
        e = PortEntry("TCP", "127.0.0.1", 3000, 123, "LISTENING", process_name="node")
        self.assertFalse(is_protected_process(e))

    def test_pid0(self):
        e = PortEntry("TCP", "0.0.0.0", 1, 0, "LISTENING", process_name="")
        self.assertTrue(is_protected_process(e))


if __name__ == "__main__":
    unittest.main()
