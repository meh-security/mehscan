#!/usr/bin/env bash
# Bash 3.2 compatible (including macOS); no PowerShell or pip packages required.
set -euo pipefail
script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# Reuse PATH without requiring Python or gh. Only an explicit force flag installs.
force=false
requested=''
source_digest=''
args=("$@")
while (($#)); do
    case "$1" in
        --force-download) force=true; shift ;;
        --version|--source-digest|--install-directory)
            if (($# < 2)); then printf 'Missing value for %s\n' "$1" >&2; exit 1; fi
            case "$1" in
                --version) requested=${2#v} ;;
                --source-digest) source_digest=$2 ;;
            esac
            shift 2 ;;
        --version=*) requested=${1#*=}; requested=${requested#v}; shift ;;
        --source-digest=*) source_digest=${1#*=}; shift ;;
        --install-directory=*) shift ;;
        *) break ;;
    esac
done
existing=$(type -P mehscan || true)
if [[ -n "$existing" && "$force" == false && $# == 0 ]]; then
    if ! reported=$("$existing" --version); then
        printf '%s\n' 'Mehscan is on PATH but its version check failed. No installation attempted.' >&2
        exit 1
    fi
    if [[ ! "$reported" =~ ^mehscan\ [0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]]; then
        printf '%s\n' 'Mehscan is on PATH but its version is invalid. No installation attempted.' >&2
        exit 1
    fi
    if [[ -n "$requested" && "$reported" != "mehscan $requested" ]]; then
        printf '%s\n' 'Mehscan is on PATH but its version differs from the request. No installation attempted.' >&2
        exit 1
    fi
    if [[ -n "$source_digest" ]]; then
        printf '%s\n' 'Mehscan is on PATH; version cannot establish source provenance. No installation attempted. Explicit verified reinstallation requires --force-download.' >&2
        exit 1
    fi
    printf '%s/%s\n' "$(CDPATH= cd -- "$(dirname -- "$existing")" && pwd)" "${existing##*/}"
    exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'Python 3.9+ is required. Install it or build Mehscan from trusted source with Cargo.' >&2
    exit 1
fi
exec python3 "$script_dir/install-mehscan.py" "${args[@]}"
