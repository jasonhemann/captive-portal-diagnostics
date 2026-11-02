#!/usr/bin/env python3
"""Create a safe-to-upload summary from one captive-portal diagnostic bundle.

Pass the timestamped *folder* as the command's positional argument, not the
similarly named .zip file. This program never uploads anything.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

OUTPUT_NAME = "safe-review.json"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse a bundle folder and optional destination without editing source code."""
    parser = argparse.ArgumentParser(
        description="Create a reduced, safe-to-share review JSON from a diagnostic bundle."
    )
    parser.add_argument(
        "bundle",
        type=Path,
        help="timestamped captive-portal diagnostic folder; do not pass its .zip file",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="optional output path (default: safe-review.json in the bundle folder)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace an existing output file",
    )
    return parser.parse_args(argv)


def read_json(path: Path) -> Any:
    """Read JSON with a useful error if a partial bundle omitted the file."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"Required bundle file is missing: {path.name}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Bundle file is not valid JSON: {path.name}: {exc}") from exc


def safe_origin(value: object) -> str | None:
    """Keep only scheme and host; discard credentials, paths, queries, and fragments."""
    if not isinstance(value, str) or not value:
        return None
    parts = urlsplit(value)
    if not parts.scheme or not parts.hostname:
        return "[non-URL redirect value omitted]"
    return urlunsplit((parts.scheme, parts.netloc.rsplit("@", 1)[-1], "", "", ""))


def header_value(headers: object, wanted_name: str) -> object | None:
    """Find one case-insensitive response-header value without retaining headers."""
    if not isinstance(headers, dict):
        return None
    for name, value in headers.items():
        if isinstance(name, str) and name.lower() == wanted_name.lower():
            return value
    return None


def command_statuses(bundle: Path) -> list[dict[str, str | None]]:
    """Retain only filenames and exit status—not command output or network values."""
    records: list[dict[str, str | None]] = []
    for path in sorted((bundle / "commands").glob("*.txt")):
        text = path.read_text(encoding="utf-8", errors="replace")
        match = re.search(r"^Exit status: (.+)$", text, flags=re.MULTILINE)
        records.append(
            {
                "file": str(path.relative_to(bundle)),
                "exit_status": match.group(1) if match else "not recorded",
            }
        )
    return records


def tcpdump_statistics(bundle: Path) -> list[str]:
    """Retain tcpdump packet counts while leaving capture details private."""
    path = bundle / "tcpdump.stderr.log"
    if not path.exists():
        return []
    packet_statistic = re.compile(
        r"^\d+ packets (?:captured|received by filter|dropped by kernel)$"
    )
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if packet_statistic.fullmatch(line.strip())
    ]


def is_redirect(status: object, headers: object) -> bool:
    """Recognize a redirect while accepting failed probes with no numeric status."""
    return (
        isinstance(status, int)
        and 300 <= status < 400
        or header_value(headers, "location") is not None
    )


def make_report(bundle: Path) -> dict[str, Any]:
    """Build a review report that omits packet, address, identifier, and token data."""
    manifest = read_json(bundle / "manifest.json")
    dns_results = read_json(bundle / "probes" / "dns-probes.json")
    web_results = read_json(bundle / "probes" / "web-probes.json")
    if (
        not isinstance(manifest, dict)
        or not isinstance(dns_results, list)
        or not isinstance(web_results, list)
    ):
        raise SystemExit("Bundle has an unexpected JSON structure; it may be incomplete.")

    pcap_path = bundle / "capture.pcap"
    safe_manifest_keys = (
        "tool",
        "version",
        "started_at",
        "finished_at",
        "capture_duration_seconds",
        "packet_capture_requested",
        "packet_capture_status",
        "capture_window_completed",
        "pcap_bytes",
    )
    return {
        "about": {
            "purpose": (
                "Safe diagnostic smoke-test review; no raw packet or network identity "
                "data included."
            ),
            "omitted": [
                "PCAP packets and packet payloads",
                "IP and MAC addresses",
                "DHCP, route, resolver, proxy, Wi-Fi, and command-output values",
                "HTTP(S) response headers, cookies, response bodies, URL paths, queries, "
                "and fragments",
            ],
        },
        "manifest": {key: manifest.get(key) for key in safe_manifest_keys},
        "pcap": {
            "present": pcap_path.is_file(),
            "bytes_on_disk": pcap_path.stat().st_size if pcap_path.is_file() else 0,
        },
        "bundle_files": sorted(
            str(path.relative_to(bundle))
            for path in bundle.rglob("*")
            if path.is_file() and path.name != OUTPUT_NAME
        ),
        "command_statuses": command_statuses(bundle),
        "tcpdump_statistics": tcpdump_statistics(bundle),
        "dns_probes": [
            {
                "hostname": item.get("hostname"),
                "outcome": item.get("outcome"),
                "address_count": len(item.get("addresses", [])),
                "error": item.get("error"),
            }
            for item in dns_results
            if isinstance(item, dict)
        ],
        "web_probes": [
            {
                "requested_host": safe_origin(item.get("url")),
                "outcome": item.get("outcome"),
                "status": item.get("status"),
                "redirect_detected": is_redirect(item.get("status"), item.get("headers")),
                "redirect_target_origin": safe_origin(
                    header_value(item.get("headers"), "location")
                ),
                "error": item.get("error"),
            }
            for item in web_results
            if isinstance(item, dict)
        ],
    }


def main(argv: list[str] | None = None) -> int:
    """Write a safe review JSON next to the original diagnostic bundle."""
    args = parse_args(argv)
    bundle = args.bundle.expanduser()
    if bundle.suffix.lower() == ".zip":
        raise SystemExit("The bundle argument must name the diagnostic folder, not its .zip file.")
    if not bundle.is_dir():
        raise SystemExit(f"Diagnostic folder not found: {bundle}")

    output_path = args.output.expanduser() if args.output else bundle / OUTPUT_NAME
    if output_path.exists() and not args.force:
        raise SystemExit(f"Output file already exists: {output_path}. Use --force to replace it.")
    output_path.write_text(
        json.dumps(make_report(bundle), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Safe review file created: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
