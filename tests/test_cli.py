from __future__ import annotations

from pathlib import Path

import pytest

from captive_portal_diagnostics import cli


@pytest.mark.parametrize(
    ("system", "route_output", "expected"),
    [
        ("Darwin", "   interface: en0\n", "en0"),
        ("Linux", "default via 192.0.2.1 dev wlan0 proto dhcp\n", "wlan0"),
        ("Linux", "", None),
    ],
)
def test_default_interface(system: str, route_output: str, expected: str | None) -> None:
    assert cli.default_interface(system, route_output) == expected


def test_default_capture_uses_privacy_reduced_snaplen(tmp_path: Path) -> None:
    command = cli.tcpdump_command("en0", tmp_path / "capture.pcap", full_payload=False)
    assert command[command.index("-s") + 1] == str(cli.DEFAULT_SNAPLEN_BYTES)
    assert command[-1] == cli.capture_filter()


def test_full_capture_uses_unlimited_snaplen(tmp_path: Path) -> None:
    command = cli.tcpdump_command("en0", tmp_path / "capture.pcap", full_payload=True)
    assert command[command.index("-s") + 1] == "0"


def test_packet_limit_detection(tmp_path: Path) -> None:
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"x" * 10)
    assert cli.pcap_limit_reached(pcap, 10)
    assert not cli.pcap_limit_reached(pcap, 11)
    assert not cli.pcap_limit_reached(pcap, None)


def test_parse_args_exposes_safe_defaults() -> None:
    args = cli.parse_args([])
    assert args.max_pcap_mib == cli.DEFAULT_MAX_PCAP_MIB
    assert not args.full_payload
