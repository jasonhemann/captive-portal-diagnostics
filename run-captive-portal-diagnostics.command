#!/bin/bash
# Double-click this file on macOS, or run it from Terminal. It intentionally
# invokes no commands with administrative privileges; Python requests permission
# only when packet capture is about to begin.
set -u

script_dir="$(cd "$(dirname "$0")" && pwd)"
cd "$script_dir"
uv run captive-portal-diagnose
status=$?

printf '\nPress Return to close this window.\n'
read -r _ || true
exit "$status"
