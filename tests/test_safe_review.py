from __future__ import annotations

import json
from pathlib import Path

from captive_portal_diagnostics import safe_review


def write_fixture_bundle(path: Path) -> None:
    (path / "commands").mkdir(parents=True)
    (path / "probes").mkdir()
    (path / "capture.pcap").write_bytes(b"pcap")
    (path / "manifest.json").write_text(
        json.dumps(
            {
                "tool": "captive-portal-diagnose",
                "packet_capture_status": "started",
                "pcap_bytes": 4,
                "interface": "en0",
            }
        ),
        encoding="utf-8",
    )
    (path / "probes" / "dns-probes.json").write_text(
        json.dumps(
            [{"hostname": "example.test", "outcome": "resolved", "addresses": ["192.0.2.1"]}]
        ),
        encoding="utf-8",
    )
    (path / "probes" / "web-probes.json").write_text(
        json.dumps(
            [
                {
                    "url": "http://probe.test/path?secret=value",
                    "status": 302,
                    "headers": {"Location": "https://portal.test/login?token=secret"},
                    "body_preview": "private body",
                }
            ]
        ),
        encoding="utf-8",
    )
    (path / "commands" / "before-interface.txt").write_text(
        "Exit status: 0\n\ninet 192.0.2.2 ether aa:bb:cc:dd:ee:ff\n",
        encoding="utf-8",
    )


def test_safe_report_omits_network_values_and_tokens(tmp_path: Path) -> None:
    write_fixture_bundle(tmp_path)

    report = safe_review.make_report(tmp_path)
    serialized = json.dumps(report)

    assert report["pcap"]["present"]
    assert report["web_probes"][0]["redirect_detected"]
    assert report["web_probes"][0]["redirect_target_origin"] == "https://portal.test"
    assert "192.0.2.1" not in serialized
    assert "aa:bb:cc:dd:ee:ff" not in serialized
    assert "secret" not in serialized
    assert "private body" not in serialized


def test_safe_review_cli_writes_generic_output(tmp_path: Path) -> None:
    write_fixture_bundle(tmp_path)

    assert safe_review.main([str(tmp_path)]) == 0
    assert (tmp_path / safe_review.OUTPUT_NAME).exists()
