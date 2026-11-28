# Sourced by the scripts/*-interop.sh scripts, with OPENSSL and BALDSSL set.
#
# Refuses a binary that is not OpenSSL 3.x or 4.x (macOS's /usr/bin/openssl is
# LibreSSL, whose output differs; baldssl has no profile before 3.0), sets
# OPENSSL_VERSION, exports the release line baldssl imitates (see README,
# "OpenSSL compatibility profiles") as BALDSSL_OPENSSL_COMPAT, and defines
# interop_pass, which counts a passing case, and interop_summary, which each
# script calls last.
# shellcheck shell=bash

OPENSSL_BANNER=$("$OPENSSL" version)
case "$OPENSSL_BANNER" in
    "OpenSSL "[34].*) ;;
    *)
        echo "$OPENSSL is $OPENSSL_BANNER: not an OpenSSL release line" \
            "baldssl has a profile for (3.x or 4.x)." >&2
        echo "Pass a real OpenSSL: make interop OPENSSL=/path/to/openssl." >&2
        echo "Found on this machine:" >&2
        "$(dirname "${BASH_SOURCE[0]}")/find-openssl.sh" >&2
        exit 2
        ;;
esac
OPENSSL_VERSION=$(awk '{print $2}' <<<"$OPENSSL_BANNER")
case "$OPENSSL_VERSION" in
    3.0.*) BALDSSL_OPENSSL_COMPAT=3.0 ;;
    3.6.*) BALDSSL_OPENSSL_COMPAT=3.6 ;;
    *) BALDSSL_OPENSSL_COMPAT=${OPENSSL_VERSION%%.*} ;;
esac
export BALDSSL_OPENSSL_COMPAT

# interop_pass NAME: count a passing case, and print it when VERBOSE=1.
interop_pass() {
    pass=$((pass + 1))
    if [[ "${VERBOSE:-0}" == 1 ]]; then
        echo "PASS $1"
    fi
}

# interop_summary NAME PASSED FAILED: print the counts and what was tested,
# and succeed only if nothing failed.
interop_summary() {
    echo "$1: $2 passed, $3 failed"
    echo "$1: tested against OpenSSL $OPENSSL_VERSION ($OPENSSL)," \
        "baldssl profile $BALDSSL_OPENSSL_COMPAT"
    [[ "$3" -eq 0 ]]
}
