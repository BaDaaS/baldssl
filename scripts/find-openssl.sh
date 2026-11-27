#!/usr/bin/env bash
#
# Lists the openssl binaries on this machine, each with its version, for the
# OPENSSL= of `make interop`. A binary that is not OpenSSL (macOS's
# /usr/bin/openssl is LibreSSL) or an OpenSSL release line baldssl has no
# profile for (before 3.0) is marked as unusable.
#
# Usage:
#   scripts/find-openssl.sh
#
# Looks on PATH, in Homebrew's prefixes (/opt/homebrew on Apple silicon,
# /usr/local on Intel, /home/linuxbrew/.linuxbrew on Linux), and in the
# default prefix of an OpenSSL built from source (/usr/local/ssl).

set -euo pipefail

candidates=()
while IFS= read -r path; do
    candidates+=("$path")
done < <(type -ap openssl || true)
for prefix in /opt/homebrew /usr/local /home/linuxbrew/.linuxbrew; do
    for path in "$prefix"/opt/openssl*/bin/openssl; do
        candidates+=("$path")
    done
done
candidates+=(/usr/local/ssl/bin/openssl)

seen=" "
found=0
for path in ${candidates[@]+"${candidates[@]}"}; do
    [[ -x "$path" ]] || continue
    real=$(readlink -f "$path")
    case "$seen" in
        *" $real "*) continue ;;
    esac
    seen="$seen$real "
    found=1
    version=$("$path" version 2>/dev/null | awk '{print $1, $2}') || true
    case "$version" in
        "OpenSSL "[34].*) printf '  OPENSSL=%-45s %s\n' "$path" "$version" ;;
        "OpenSSL "*) printf '  %-53s %s (no profile)\n' "$path" "$version" ;;
        *) printf '  %-53s %s (not OpenSSL)\n' "$path" "${version:-unknown}" ;;
    esac
done
if [[ "$found" -eq 0 ]]; then
    echo "  none found; install OpenSSL (brew install openssl@3)"
fi
