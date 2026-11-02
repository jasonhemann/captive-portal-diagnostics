#!/bin/bash
# Double-click this file on macOS, or run it from Terminal. It intentionally
# invokes no shell commands with administrative privileges; Python will request
# permission only when packet capture is about to begin.
set -u

script_dir="$(cd "$(dirname "$0")" && pwd)"
python3 "$script_dir/captive_portal_diagnose.py"
status=$?

printf '\nPress Return to close this window.\n'
read -r _ || true
exit "$status"
