# Captive Portal Diagnostics

This is a standalone, dependency-free diagnostic for public Wi-Fi networks that
will not finish their sign-in or captive-portal flow. It collects a time-bounded
support bundle with DNS, routing, TCP, HTTP, HTTPS, and packet-level evidence.

## Quick use

Use it only on a device and network connection you own or are authorized to
diagnose. The bundle can contain sensitive network identifiers, portal URLs,
cookies, and unencrypted HTTP content; its ZIP file is not encrypted.

Connect to the problematic Wi-Fi, then open Terminal and run:

```sh
cd /path/to/captive-portal-diagnostics
python3 captive_portal_diagnose.py
```

To install commands from a source checkout:

```sh
python3 -m pip install .
captive-portal-diagnose
```

For a short test run, use `python3 captive_portal_diagnose.py --duration 60`.
The tool asks before collecting anything and then asks for your administrator
password solely to start `tcpdump`. Type the password normally; Terminal will
not display any characters. It opens a browser detection page and records for
five minutes by default. Press `Control-C` to stop early and finalize the files.

On macOS, you can instead double-click `run-captive-portal-diagnostics.command`.
If macOS blocks it, Control-click the file, choose **Open**, and confirm.

Each run writes a timestamped folder and ZIP to
`~/Desktop/CaptivePortalDiagnostics`. By default, packet snapshots are limited to
512 bytes and capture stops around 128 MiB. Use `--full-payload` only when a
trusted support team specifically needs complete packets; use `--max-pcap-mib 0`
only when you deliberately accept an unlimited capture.

## Make a safe review file for an issue report or chat

Do **not** upload the ZIP, `capture.pcap`, raw command files, or raw probe files
to a public issue or chat. Instead, create the deliberately reduced review file:

```sh
python3 make_safe_review.py ~/Desktop/CaptivePortalDiagnostics/captive-portal-YYYYMMDD-HHMMSS
```

After installation, the equivalent command is:

```sh
captive-portal-safe-review ~/Desktop/CaptivePortalDiagnostics/captive-portal-YYYYMMDD-HHMMSS
```

Upload only the reported `safe-review.json` file. It retains run status, artifact
presence, command exit statuses, packet-capture counts, and simplified DNS/web-
probe outcomes. It omits packet contents, IP/MAC addresses, Wi-Fi/DHCP/router/
proxy values, cookies, headers, response bodies, URL paths, query strings, and
fragments.

## Evidence retained by the full diagnostic

- Network configuration before and after the attempt: interface addresses,
  default route, routing table, resolver setup, proxy setup, Wi-Fi network, and
  DHCP lease where the operating system provides it.
- Active DNS queries/responses and HTTP/HTTPS connectivity probes.
- A PCAP for the selected network interface, including ARP, ICMP/ICMPv6, DHCP,
  DNS, HTTP, HTTPS, TCP setup/teardown, and TLS connection metadata.
- A manifest, tcpdump diagnostics, and SHA-256 checksums.

The script supports macOS and Linux and needs Python 3.10+ plus the operating
system's `tcpdump` for packet capture. Use `python3 captive_portal_diagnose.py
--help` to see all options.

## Development

```sh
uv sync --group dev
make check
```

The test suite uses fixtures and never starts a live capture. Before publishing,
enable GitHub CodeQL default setup and keep real diagnostic bundles, PCAPs, ZIPs,
and credentials out of version control.
