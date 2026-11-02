#!/usr/bin/env python3
"""Collect a time-bounded diagnostic bundle for captive-portal failures.

This script has no third-party Python dependencies.  On macOS and Linux it uses
the operating system's ``tcpdump`` command for the packet capture because a PCAP
is the most complete evidence an IT network team can inspect later.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

from . import __version__

TOOL_NAME = "captive-portal-diagnose"
TOOL_VERSION = __version__
DEFAULT_DURATION_SECONDS = 300
PROBE_TIMEOUT_SECONDS = 12
MAX_COMMAND_OUTPUT_BYTES = 1_000_000
MAX_BODY_PREVIEW_BYTES = 8_192
DEFAULT_SNAPLEN_BYTES = 512
DEFAULT_MAX_PCAP_MIB = 128
DETECTION_URL = "http://captive.apple.com/hotspot-detect.html"

DNS_HOSTS = (
    "captive.apple.com",
    "connectivitycheck.gstatic.com",
    "www.msftconnecttest.com",
)
HTTP_PROBES = (
    "http://captive.apple.com/hotspot-detect.html",
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://www.msftconnecttest.com/connecttest.txt",
)
HTTPS_PROBES = (
    "https://www.apple.com/library/test/success.html",
    "https://www.gstatic.com/generate_204",
)


@dataclass(frozen=True)
class CliArgs:
    """Arguments supplied by the person collecting the diagnostic."""

    duration: int
    interface: str | None
    output_dir: Path
    open_browser: bool
    packet_capture: bool
    full_payload: bool
    max_pcap_mib: int
    assume_yes: bool


@dataclass(frozen=True)
class CommandResult:
    """The retained result of a read-only system diagnostic command."""

    command: list[str]
    returncode: int | None
    output: str
    timed_out: bool


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Do not follow redirects: a captive-portal redirect is diagnostic evidence."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_args(argv: list[str] | None = None) -> CliArgs:
    """Read command-line options, keeping the normal path intentionally simple."""
    parser = argparse.ArgumentParser(
        description="Capture a time-limited Wi-Fi captive-portal diagnostic bundle for IT.",
        epilog=(
            "The default packet capture may contain portal credentials, cookies, and "
            "web traffic. Share the resulting bundle only with trusted support."
        ),
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=DEFAULT_DURATION_SECONDS,
        metavar="SECONDS",
        help="how long to capture while you sign in (default: 300)",
    )
    parser.add_argument(
        "--interface", help="network interface to capture, for example en0 or wlan0"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path.home() / "Desktop" / "CaptivePortalDiagnostics",
        help="directory in which to save bundles (default: Desktop/CaptivePortalDiagnostics)",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="do not open a browser to the captive-portal detection page",
    )
    parser.add_argument(
        "--no-packet-capture",
        action="store_true",
        help="collect context and probes only; omit the PCAP (less useful to IT)",
    )
    parser.add_argument(
        "--full-payload",
        action="store_true",
        help=(
            "record complete packets instead of the privacy-reduced 512-byte packet "
            "snapshots; may create a much larger, more sensitive PCAP"
        ),
    )
    parser.add_argument(
        "--max-pcap-mib",
        type=int,
        default=DEFAULT_MAX_PCAP_MIB,
        metavar="MIB",
        help=(
            "stop packet capture once this approximate size is reached; use 0 for no "
            f"size limit (default: {DEFAULT_MAX_PCAP_MIB})"
        ),
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="confirm the privacy notice without an interactive prompt",
    )
    namespace = parser.parse_args(argv)
    duration = int(namespace.duration)
    if not 15 <= duration <= 3_600:
        parser.error("--duration must be between 15 and 3600 seconds")
    max_pcap_mib = int(namespace.max_pcap_mib)
    if not 0 <= max_pcap_mib <= 2_048:
        parser.error("--max-pcap-mib must be between 0 and 2048")
    return CliArgs(
        duration=duration,
        interface=namespace.interface,
        output_dir=Path(namespace.output_dir).expanduser(),
        open_browser=not bool(namespace.no_browser),
        packet_capture=not bool(namespace.no_packet_capture),
        full_payload=bool(namespace.full_payload),
        max_pcap_mib=max_pcap_mib,
        assume_yes=bool(namespace.yes),
    )


def is_supported_platform() -> bool:
    """Return whether this version has the needed platform collection commands."""
    return platform.system() in {"Darwin", "Linux"}


def confirm_privacy_notice(
    assume_yes: bool, packet_capture: bool, output: TextIO = sys.stdout
) -> bool:
    """Obtain deliberate consent before potentially sensitive artifacts are created."""
    if assume_yes:
        return True
    capture_notice = (
        " It also records packets, which can include portal credentials, cookies, device "
        "addresses, and unencrypted web content."
        if packet_capture
        else " Packet capture is disabled for this run."
    )
    print(
        "\nPrivacy notice: this tool records network configuration and web-probe results; "
        "those can include network addresses, portal URLs, and response content."
        f"{capture_notice} Only share the bundle with trusted IT support through an "
        "approved secure channel.",
        file=output,
    )
    try:
        answer = input("Start the diagnostic capture? [y/N] ").strip().lower()
    except EOFError:
        print("No confirmation received; nothing was captured.", file=output)
        return False
    return answer in {"y", "yes"}


def command_text(command: list[str]) -> str:
    """Format a command for a log without ever invoking a shell."""
    return " ".join(repr(part) if any(ch.isspace() for ch in part) else part for part in command)


def truncate_output(value: str) -> str:
    """Keep an unexpectedly verbose system command from filling the user's disk."""
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= MAX_COMMAND_OUTPUT_BYTES:
        return value
    shortened = encoded[:MAX_COMMAND_OUTPUT_BYTES].decode("utf-8", errors="replace")
    return f"{shortened}\n[output truncated at {MAX_COMMAND_OUTPUT_BYTES} bytes]\n"


def run_command(command: list[str], timeout: int = 15) -> CommandResult:
    """Run one bounded, read-only command and retain a usable failure record."""
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
            errors="replace",
        )
    except FileNotFoundError:
        return CommandResult(command, None, "Command not available on this computer.\n", False)
    except subprocess.TimeoutExpired as exc:
        stdout = (
            exc.stdout.decode("utf-8", errors="replace")
            if isinstance(exc.stdout, bytes)
            else exc.stdout or ""
        )
        stderr = (
            exc.stderr.decode("utf-8", errors="replace")
            if isinstance(exc.stderr, bytes)
            else exc.stderr or ""
        )
        return CommandResult(
            command,
            None,
            truncate_output(f"{stdout}{stderr}\nCommand timed out after {timeout} seconds.\n"),
            True,
        )
    return CommandResult(
        command,
        completed.returncode,
        truncate_output(f"{completed.stdout}{completed.stderr}"),
        False,
    )


def write_command_result(path: Path, result: CommandResult) -> None:
    """Write a readable command transcript alongside the rest of the evidence."""
    path.parent.mkdir(parents=True, exist_ok=True)
    status = "timed out" if result.timed_out else str(result.returncode)
    path.write_text(
        f"Collected: {utc_now()}\nCommand: {command_text(result.command)}\n"
        f"Exit status: {status}\n\n{result.output}",
        encoding="utf-8",
    )


def route_command_for(system: str) -> list[str]:
    """Select the normal default-route query for macOS or Linux."""
    return (
        ["route", "-n", "get", "default"]
        if system == "Darwin"
        else ["ip", "route", "show", "default"]
    )


def default_interface(system: str, route_output: str) -> str | None:
    """Find the default-route interface in platform-specific route output."""
    if system == "Darwin":
        match = re.search(r"^\s*interface:\s*(\S+)", route_output, flags=re.MULTILINE)
    else:
        match = re.search(r"\bdev\s+(\S+)", route_output)
    return match.group(1) if match else None


def snapshot_commands(system: str, interface: str | None) -> list[tuple[str, list[str]]]:
    """Return concise, read-only network-state queries for the active platform."""
    common = [
        ("default-route", route_command_for(system)),
        ("routing-table", ["netstat", "-rn"]),
        (
            "resolver-configuration",
            ["scutil", "--dns"] if system == "Darwin" else ["resolvectl", "status"],
        ),
    ]
    if system == "Darwin":
        commands = [
            ("system-version", ["sw_vers"]),
            ("network-reachability", ["scutil", "--nwi"]),
            ("proxy-configuration", ["scutil", "--proxy"]),
            ("network-hardware", ["networksetup", "-listallhardwareports"]),
            ("wifi-service", ["networksetup", "-getinfo", "Wi-Fi"]),
            *common,
        ]
        if interface:
            commands.extend(
                [
                    ("interface", ["ifconfig", interface]),
                    ("wifi-network", ["networksetup", "-getairportnetwork", interface]),
                    ("dhcp-lease", ["ipconfig", "getpacket", interface]),
                ]
            )
        return commands

    commands = [
        ("kernel", ["uname", "-a"]),
        ("network-manager", ["nmcli", "device", "show"]),
        ("wireless-interfaces", ["iw", "dev"]),
        *common,
    ]
    if interface:
        commands.extend(
            [
                ("interface", ["ip", "address", "show", "dev", interface]),
                ("wifi-link", ["iw", "dev", interface, "link"]),
            ]
        )
    return commands


def collect_snapshot(commands_dir: Path, system: str, interface: str | None, phase: str) -> None:
    """Save a before or after snapshot without treating missing tools as fatal."""
    for name, command in snapshot_commands(system, interface):
        write_command_result(commands_dir / f"{phase}-{name}.txt", run_command(command))


def capture_filter() -> str:
    """Limit PCAP contents to protocols relevant to joining and using a portal."""
    terms = (
        "arp",
        "icmp",
        "icmp6",
        "udp port 53",
        "udp port 67",
        "udp port 68",
        "tcp port 53",
        "tcp port 80",
        "tcp port 443",
    )
    return f"({' or '.join(terms)})"


def tcpdump_command(interface: str, pcap_path: Path, full_payload: bool) -> list[str]:
    """Build the privileged tcpdump process without shell interpolation."""
    return [
        "sudo",
        "tcpdump",
        "-i",
        interface,
        "-n",
        "-s",
        "0" if full_payload else str(DEFAULT_SNAPLEN_BYTES),
        "-U",
        "-w",
        str(pcap_path),
        capture_filter(),
    ]


def start_packet_capture(
    interface: str, pcap_path: Path, stderr_path: Path, full_payload: bool
) -> subprocess.Popen[bytes] | None:
    """Ask once for sudo authorization and launch tcpdump in its own process group."""
    authorization = subprocess.run(["sudo", "-v"], check=False)
    if authorization.returncode != 0:
        return None
    stderr_file = stderr_path.open("wb")
    try:
        return subprocess.Popen(
            tcpdump_command(interface, pcap_path, full_payload),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=stderr_file,
            start_new_session=True,
        )
    finally:
        stderr_file.close()


def stop_packet_capture(process: subprocess.Popen[bytes] | None) -> None:
    """Gracefully stop tcpdump so its PCAP footer/statistics are finalized."""
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGINT)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def body_preview(response: Any) -> str:
    """Read only a small, UTF-8-safe preview of a portal response body."""
    body = response.read(MAX_BODY_PREVIEW_BYTES)
    return body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)


def http_probe(url: str) -> dict[str, Any]:
    """Record a direct HTTP(S) probe, including a portal's redirect response."""
    request = urllib.request.Request(url, headers={"User-Agent": f"{TOOL_NAME}/{TOOL_VERSION}"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirectHandler())
    result: dict[str, Any] = {"url": url, "started_at": utc_now()}
    try:
        with opener.open(request, timeout=PROBE_TIMEOUT_SECONDS) as response:
            result.update(
                outcome="response",
                status=int(response.status),
                final_url=response.geturl(),
                headers=dict(response.headers.items()),
                body_preview=body_preview(response),
            )
    except urllib.error.HTTPError as exc:
        result.update(
            outcome="http_error_or_redirect",
            status=exc.code,
            final_url=exc.geturl(),
            headers=dict(exc.headers.items()) if exc.headers else {},
            body_preview=body_preview(exc),
        )
    except (OSError, urllib.error.URLError, ValueError) as exc:
        result.update(outcome="connection_error", error=str(getattr(exc, "reason", exc)))
    result["finished_at"] = utc_now()
    return result


def dns_probe(hostname: str) -> dict[str, Any]:
    """Resolve one recognisable endpoint through the active system resolver."""
    result: dict[str, Any] = {"hostname": hostname, "started_at": utc_now()}
    try:
        addresses = socket.getaddrinfo(hostname, 80, type=socket.SOCK_STREAM)
        result.update(outcome="resolved", addresses=sorted({item[4][0] for item in addresses}))
    except socket.gaierror as exc:
        result.update(outcome="resolution_error", error=str(exc))
    result["finished_at"] = utc_now()
    return result


def collect_active_probes(probes_dir: Path) -> None:
    """Generate DNS/HTTP/HTTPS evidence while the PCAP is active."""
    probes_dir.mkdir(parents=True, exist_ok=True)
    (probes_dir / "dns-probes.json").write_text(
        json.dumps([dns_probe(hostname) for hostname in DNS_HOSTS], indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    (probes_dir / "web-probes.json").write_text(
        json.dumps(
            [http_probe(url) for url in (*HTTP_PROBES, *HTTPS_PROBES)], indent=2, sort_keys=True
        )
        + "\n",
        encoding="utf-8",
    )
    if shutil.which("dig"):
        for hostname in DNS_HOSTS:
            result = run_command(["dig", "+time=2", "+tries=1", hostname], timeout=8)
            write_command_result(probes_dir / f"dig-{hostname.replace('.', '-')}.txt", result)
    else:
        (probes_dir / "dig-notes.txt").write_text(
            "dig was not available; DNS results above came from the system resolver.\n",
            encoding="utf-8",
        )


def open_detection_page() -> bool:
    """Open a known plain-HTTP URL so the OS/browser can expose a portal page."""
    try:
        return bool(webbrowser.open(DETECTION_URL, new=1))
    except webbrowser.Error:
        return False


def make_bundle_directory(base: Path) -> Path:
    """Create a unique timestamped bundle folder without overwriting old captures."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    candidate = base / f"captive-portal-{stamp}"
    suffix = 1
    while candidate.exists():
        suffix += 1
        candidate = base / f"captive-portal-{stamp}-{suffix}"
    candidate.mkdir(parents=True)
    return candidate


def write_bundle_readme(bundle_dir: Path) -> None:
    """Include sharing and interpretation guidance in every support bundle."""
    (bundle_dir / "README.txt").write_text(
        "Captive portal diagnostic bundle\n"
        "===============================\n\n"
        "This bundle is for a network administrator investigating a Wi-Fi sign-in failure. "
        "It is not encrypted. Send it only through your organization's approved secure "
        "support channel.\n\n"
        "Contents\n--------\n"
        "- manifest.json: time, platform, selected interface, and collection status\n"
        "- commands/: before/after network state, route, resolver, Wi-Fi, DHCP, and proxy data\n"
        "- probes/: DNS lookups plus HTTP/HTTPS connectivity checks and redirect evidence\n"
        "- capture.pcap: packet capture, when administrator permission was granted\n"
        "- tcpdump.stderr.log: tcpdump startup/final statistics\n"
        "- SHA256SUMS: integrity checks for the bundle files\n\n"
        "PCAP scope\n----------\n"
        "The capture is limited to ARP, ICMP/ICMPv6, DHCP, DNS, HTTP (TCP 80), and HTTPS "
        "(TCP 443) on the selected interface. It preserves TCP SYN/FIN/RST packets, DNS "
        "requests/responses, unencrypted HTTP portal exchanges, and encrypted HTTPS "
        "connection/TLS metadata. HTTPS page contents are not decrypted.\n\n"
        "The capture can still contain sensitive information such as portal credentials sent "
        "over HTTP, cookies, device addresses, portal URLs, and web content. Keep it private "
        "and delete local copies after support confirms it is no longer needed.\n",
        encoding="utf-8",
    )


def write_checksums(bundle_dir: Path) -> None:
    """Create conventional SHA-256 checksums for all retained artifacts."""
    entries: list[str] = []
    for path in sorted(bundle_dir.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            entries.append(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(bundle_dir)}"
            )
    (bundle_dir / "SHA256SUMS").write_text("\n".join(entries) + "\n", encoding="utf-8")


def archive_bundle(bundle_dir: Path) -> Path:
    """Create a portable but deliberately unencrypted ZIP next to the folder."""
    archive_path = bundle_dir.parent / f"{bundle_dir.name}.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in bundle_dir.rglob("*"):
            if path.is_file():
                archive.write(path, path.relative_to(bundle_dir.parent))
    return archive_path


def pcap_limit_reached(pcap_path: Path, max_pcap_bytes: int | None) -> bool:
    """Return whether a configured packet-capture size limit has been reached."""
    return (
        max_pcap_bytes is not None
        and pcap_path.exists()
        and pcap_path.stat().st_size >= max_pcap_bytes
    )


def wait_for_capture_window(
    duration: int,
    pcap_path: Path,
    max_pcap_bytes: int | None,
    output: TextIO = sys.stdout,
) -> tuple[bool, bool]:
    """Count down, supporting early exit and a configured packet-capture cap."""
    end_time = time.monotonic() + duration
    next_notice = duration
    try:
        while True:
            remaining = max(0, int(end_time - time.monotonic()))
            if pcap_limit_reached(pcap_path, max_pcap_bytes):
                print("Packet-capture size limit reached; finalizing files.", file=output)
                return False, True
            if remaining == 0:
                print("Capture time is complete; finalizing files.", file=output)
                return True, False
            if remaining <= next_notice:
                minutes, seconds = divmod(remaining, 60)
                print(
                    f"Capturing… {minutes}:{seconds:02d} remaining. Press Ctrl-C to finish early.",
                    file=output,
                )
                next_notice = remaining - 30
            time.sleep(min(1.0, end_time - time.monotonic()))
    except KeyboardInterrupt:
        print("Ending capture early and finalizing files.", file=output)
        return False, False


def main(argv: list[str] | None = None) -> int:
    """Run the complete guided workflow and report where the bundle was saved."""
    args = parse_args(argv)
    system = platform.system()
    if not is_supported_platform():
        print(
            f"{TOOL_NAME} supports macOS and Linux; this computer reports {system}.",
            file=sys.stderr,
        )
        return 2
    if not confirm_privacy_notice(args.assume_yes, args.packet_capture):
        return 0
    if args.packet_capture and shutil.which("tcpdump") is None:
        print("tcpdump is required for packet capture but was not found.", file=sys.stderr)
        return 2

    route_result = run_command(route_command_for(system))
    interface = args.interface or default_interface(system, route_result.output)
    if args.packet_capture and interface is None:
        print(
            "Could not identify the active network interface. Re-run with --interface "
            "(for example en0).",
            file=sys.stderr,
        )
        return 2

    bundle_dir = make_bundle_directory(args.output_dir)
    commands_dir = bundle_dir / "commands"
    write_command_result(commands_dir / "before-default-route.txt", route_result)
    pcap_path = bundle_dir / "capture.pcap"
    max_pcap_bytes = args.max_pcap_mib * 1024 * 1024 or None

    metadata: dict[str, Any] = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "started_at": utc_now(),
        "platform": platform.platform(),
        "python": sys.version,
        "interface": interface,
        "capture_duration_seconds": args.duration,
        "packet_capture_requested": args.packet_capture,
        "packet_capture_filter": capture_filter() if args.packet_capture else None,
        "packet_capture_snaplen_bytes": 0 if args.full_payload else DEFAULT_SNAPLEN_BYTES,
        "packet_capture_max_bytes": max_pcap_bytes,
        "browser_open_requested": args.open_browser,
    }
    process: subprocess.Popen[bytes] | None = None
    capture_started = False
    limit_reached = False
    try:
        collect_snapshot(commands_dir, system, interface, "before")
        if args.packet_capture:
            assert interface is not None
            print(f"Requesting permission to capture on {interface}.")
            process = start_packet_capture(
                interface,
                pcap_path,
                bundle_dir / "tcpdump.stderr.log",
                args.full_payload,
            )
            time.sleep(1)
            capture_started = process is not None and process.poll() is None
            metadata["packet_capture_status"] = "started" if capture_started else "not_started"
            if not capture_started:
                print(
                    "Capture did not start; continuing with context and probe logs only.",
                    file=sys.stderr,
                )

        print("Running DNS and web connectivity checks.")
        collect_active_probes(bundle_dir / "probes")
        limit_reached = pcap_limit_reached(pcap_path, max_pcap_bytes)
        if limit_reached:
            print("Packet-capture size limit reached; finalizing files.", file=sys.stderr)
        if args.open_browser:
            metadata["browser_opened"] = open_detection_page()
            if metadata["browser_opened"]:
                print(
                    "A browser page was opened. Complete or retry the Wi-Fi sign-in while "
                    "capture continues."
                )
            else:
                print(f"Could not open a browser. Visit {DETECTION_URL} while capture continues.")
        if capture_started and not limit_reached:
            completed, limit_reached = wait_for_capture_window(
                args.duration,
                pcap_path,
                max_pcap_bytes,
            )
            metadata["capture_window_completed"] = completed
        else:
            metadata["capture_window_completed"] = False
    finally:
        stop_packet_capture(process)
        collect_snapshot(commands_dir, system, interface, "after")
        metadata["finished_at"] = utc_now()
        metadata["pcap_bytes"] = pcap_path.stat().st_size if pcap_path.exists() else 0
        metadata["packet_capture_limit_reached"] = limit_reached
        (bundle_dir / "manifest.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        write_bundle_readme(bundle_dir)
        write_checksums(bundle_dir)

    archive_path = archive_bundle(bundle_dir)
    print("\nDiagnostic bundle created.")
    print(f"Folder: {bundle_dir}")
    print(f"ZIP for trusted IT support: {archive_path}")
    if args.packet_capture and not capture_started:
        print(
            "Note: no packet capture was recorded; the bundle contains context and probe "
            "results only."
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
