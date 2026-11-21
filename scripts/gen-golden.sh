#!/usr/bin/env bash
#
# Regenerates the golden outputs used by `cargo test` from real OpenSSL
# binaries, one directory per compatibility profile:
#   tests/fixtures/golden/v3/<cert>/<case>.out   (OpenSSL 3.5)
#   tests/fixtures/golden/v4/<cert>/<case>.out   (OpenSSL 4.1)
# for every certificate in tests/fixtures/certs and every case in
# tests/fixtures/cases.txt.
#
# Usage:
#   scripts/gen-golden.sh <openssl-3.5> <openssl-4.1>
#   scripts/gen-golden.sh --certs <openssl>   # (re)create the certificates
#

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
FIX="$ROOT/tests/fixtures"

if [[ "${1:-}" == "--certs" && "$#" -eq 2 ]]; then
    rm -f "$FIX"/certs/*.crt
    exec "$ROOT/scripts/gen-certs.sh" "$2" "$FIX/certs"
fi
if [[ "$#" -ne 2 ]]; then
    echo "usage: $0 <openssl-3.5> <openssl-4.1> | --certs <openssl>" >&2
    exit 2
fi

render() {
    # render <openssl> <profile-dir>
    local openssl=$1 dir=$2
    rm -rf "$dir"
    for cert in "$FIX"/certs/*.crt; do
        local base
        base=$(basename "$cert" .crt)
        mkdir -p "$dir/$base"
        while IFS='|' read -r case args; do
            case "$case" in '' | '#'*) continue ;; esac
            # shellcheck disable=SC2086 # args is a word list by design
            "$openssl" x509 -in "$cert" $args >"$dir/$base/$case.out"
        done <"$FIX/cases.txt"
    done
    "$openssl" version >"$dir/VERSION"
}

render "$1" "$FIX/golden/v3"
render "$2" "$FIX/golden/v4"
echo "golden files written for: $(cat "$FIX/golden/v3/VERSION") and" \
    "$(cat "$FIX/golden/v4/VERSION")"
