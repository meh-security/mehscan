#!/usr/bin/env bash
# Bash 3.2 compatible (including macOS); no PowerShell or pip packages required.
set -euo pipefail
script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'Python 3.9+ is required. Install it or build Mehscan from trusted source with Cargo.' >&2
    exit 1
fi
exec python3 "$script_dir/install-mehscan.py" "$@"
