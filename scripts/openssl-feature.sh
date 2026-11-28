#!/usr/bin/env bash
#
# The Cargo feature of the OpenSSL release line baldssl imitates for an
# OpenSSL binary: openssl-3-0 for 3.0, openssl-3-6 for 3.6, openssl-3-5 for
# the other 3.x, openssl-4 for 4.x.
#
# Usage:
#   scripts/openssl-feature.sh <path/to/openssl>
#       prints the feature
#   scripts/openssl-feature.sh <path/to/openssl> <path/to/baldssl>
#       prints the feature, and fails unless baldssl was built with it
#
set -euo pipefail

if [[ "$#" -lt 1 || "$#" -gt 2 ]]; then
    echo "usage: $0 <openssl> [<baldssl>]" >&2
    exit 2
fi
banner=$("$1" version)
case "$banner" in
    "OpenSSL 3.0."*) feature=openssl-3-0 ;;
    "OpenSSL 3.6."*) feature=openssl-3-6 ;;
    "OpenSSL 3."*) feature=openssl-3-5 ;;
    "OpenSSL 4."*) feature=openssl-4 ;;
    *)
        echo "$1 is $banner: not an OpenSSL release line baldssl has a" \
            "profile for (3.x or 4.x)." >&2
        echo "Pass a real OpenSSL: make interop OPENSSL=/path/to/openssl." >&2
        echo "Found on this machine:" >&2
        "$(dirname "$0")/find-openssl.sh" >&2
        exit 1
        ;;
esac
if [[ "$#" -eq 2 ]] && ! "$2" version | grep -qF "(feature $feature)"; then
    echo "$0: $2 is not built for $banner: build it with" >&2
    echo "  make build-for-openssl OPENSSL=$1" >&2
    exit 1
fi
echo "$feature"
