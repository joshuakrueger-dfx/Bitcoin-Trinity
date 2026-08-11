#!/usr/bin/env python3
"""Reject published compose ports that are not bound to loopback."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "docker" / "compose.yml"

# Short-syntax published host mappings only (this repo's style).
# IP:HOST:CONTAINER or HOST:CONTAINER, optional quotes and trailing comment.
PORT_IP = re.compile(
    r'^\s*-\s*["\']?(\d+\.\d+\.\d+\.\d+):(\d+):(\d+)["\']?\s*(?:#.*)?$'
)
PORT_HOST_ONLY = re.compile(
    r'^\s*-\s*["\']?(\d+):(\d+)["\']?\s*(?:#.*)?$'
)


def published_ports(text: str) -> list[tuple[str, str | None, str, str]]:
    """Return list of (raw_line, host_ip_or_None, host_port, container_port)."""
    results: list[tuple[str, str | None, str, str]] = []
    in_ports = False
    ports_indent: int | None = None
    for line in text.splitlines():
        if re.match(r"^\s*ports:\s*$", line):
            in_ports = True
            ports_indent = len(line) - len(line.lstrip(" "))
            continue
        if not in_ports:
            continue
        if not line.strip() or line.strip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        # Left the ports block (sibling key or less-indented content).
        if (
            ports_indent is not None
            and indent <= ports_indent
            and not line.lstrip().startswith("-")
        ):
            in_ports = False
            if re.match(r"^\s*ports:\s*$", line):
                in_ports = True
                ports_indent = indent
            continue
        m_ip = PORT_IP.match(line)
        if m_ip:
            results.append(
                (line.strip(), m_ip.group(1), m_ip.group(2), m_ip.group(3))
            )
            continue
        m_host = PORT_HOST_ONLY.match(line)
        if m_host:
            results.append(
                (line.strip(), None, m_host.group(1), m_host.group(2))
            )
            continue
        if line.lstrip().startswith("-"):
            results.append((line.strip(), None, "?", "?"))
    return results


class TestComposeLoopbackBinds(unittest.TestCase):
    def test_compose_exists(self) -> None:
        self.assertTrue(COMPOSE.is_file())

    def test_every_published_port_binds_loopback(self) -> None:
        text = COMPOSE.read_text(encoding="utf-8")
        ports = published_ports(text)
        self.assertGreater(len(ports), 0, "expected at least one published port")
        bad: list[str] = []
        for raw, ip, host, container in ports:
            if ip != "127.0.0.1":
                bad.append(
                    f"{raw}  (host_ip={ip!r}, host_port={host}, container={container})"
                )
        self.assertEqual(
            bad,
            [],
            "published ports must bind 127.0.0.1 (static test credentials):\n  "
            + "\n  ".join(bad),
        )

    def test_detector_rejects_all_interfaces_mapping(self) -> None:
        """The detector itself must fail the former all-interfaces form."""
        sample = """
services:
  bitcoind:
    ports:
      - "18443:18443"
      - "127.0.0.1:18444:18444"
"""
        ports = published_ports(sample)
        self.assertEqual(len(ports), 2)
        open_binds = [p for p in ports if p[1] != "127.0.0.1"]
        self.assertEqual(len(open_binds), 1)
        self.assertIsNone(open_binds[0][1])
        self.assertEqual(open_binds[0][2], "18443")


if __name__ == "__main__":
    unittest.main()
