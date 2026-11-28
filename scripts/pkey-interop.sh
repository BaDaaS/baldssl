#!/usr/bin/env bash
#
# Differential tests of `pkey` against a real OpenSSL, for every key of
# tests/fixtures/keys/keypairs.txt: reading the PKCS#8 key (PEM or DER)
# and the public key (-pubin), and writing, printing (-text, -text_pub)
# and checking them print what OpenSSL prints, byte for byte, under the
# release line of the OpenSSL tested. A private key written with -out is
# readable by its owner only, as OpenSSL creates it. A secret whose first
# byte is zero is checked too.
#
# Usage:
#   scripts/pkey-interop.sh <path/to/openssl> <path/to/baldssl>
#
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
    echo "usage: $0 <openssl> <baldssl>" >&2
    exit 2
fi
OPENSSL=$1
BALDSSL=$2
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/baldssl-pkey.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=scripts/interop-profile.sh
source "$ROOT/scripts/interop-profile.sh"
pass=0
fail=0

same() {
    # same <label> <args...>: both print the same, and agree on success.
    local label=$1
    shift
    local ro=0 rb=0
    "$OPENSSL" pkey "$@" >"$WORK/o.out" 2>/dev/null || ro=$?
    "$BALDSSL" pkey "$@" >"$WORK/b.out" 2>/dev/null || rb=$?
    if [[ "$ro" -eq 0 && "$rb" -eq 0 ]] && cmp -s "$WORK/o.out" "$WORK/b.out"; then
        interop_pass "$label"
    else
        echo "FAIL $label: exit $ro and $rb, or outputs differ"
        fail=$((fail + 1))
    fi
}

mode() { perl -e 'printf "%o", (stat shift)[2] & 0777' "$1"; }
unhex() { perl -e 'print pack("H*", shift)' "$1"; }

private_args=("" "-outform DER" "-pubout" "-pubout -outform DER" "-text -noout"
    "-text_pub -noout" "-check -noout" "-pubcheck -noout" "-text")
public_args=("" "-outform DER" "-text -noout" "-noout -pubcheck")
n=0
while read -r curve _ _ pkcs8; do
    n=$((n + 1))
    unhex "$pkcs8" >"$WORK/k.der"
    "$OPENSSL" pkey -in "$WORK/k.der" -inform DER -out "$WORK/k.pem"
    "$OPENSSL" pkey -in "$WORK/k.der" -inform DER -pubout -out "$WORK/p.pem"
    "$OPENSSL" pkey -in "$WORK/k.der" -inform DER -pubout -outform DER \
        -out "$WORK/p.der"
    for args in "${private_args[@]}"; do
        read -r -a extra <<<"$args"
        same "$curve $n PEM ${args:-(none)}" -in "$WORK/k.pem" ${extra[@]+"${extra[@]}"}
        same "$curve $n DER ${args:-(none)}" -in "$WORK/k.der" -inform DER \
            ${extra[@]+"${extra[@]}"}
    done
    for args in "${public_args[@]}"; do
        read -r -a extra <<<"$args"
        same "$curve $n -pubin PEM ${args:-(none)}" -pubin -in "$WORK/p.pem" \
            ${extra[@]+"${extra[@]}"}
        same "$curve $n -pubin DER ${args:-(none)}" -pubin -in "$WORK/p.der" \
            -inform DER ${extra[@]+"${extra[@]}"}
    done
    "$BALDSSL" pkey -in "$WORK/k.pem" -out "$WORK/written.pem"
    if [[ "$(mode "$WORK/written.pem")" == 600 ]] &&
        cmp -s "$WORK/written.pem" "$WORK/k.pem"; then
        interop_pass "$curve $n: -out key file mode"
    else
        echo "FAIL $curve $n: -out key file mode $(mode "$WORK/written.pem")"
        fail=$((fail + 1))
    fi
    rm -f "$WORK/written.pem"
done < <(grep -v '^#' "$ROOT/tests/fixtures/keys/keypairs.txt")

# A secret whose first byte is zero, which no fixture key has: OpenSSL
# prints and writes it at the full length of the order. The key is built
# with its public point, as OpenSSL writes every key it makes.
secret="00$(perl -e 'printf "%02x", $_ for 0x81..0x9f')"
unhex "30310201010420${secret}a00a06082a8648ce3d030107" >"$WORK/zero0.der"
point=$("$OPENSSL" pkey -in "$WORK/zero0.der" -inform DER -pubout -outform DER |
    tail -c 65 | perl -e 'local $/; print unpack("H*", <STDIN>)')
unhex "30770201010420${secret}a00a06082a8648ce3d030107a144034200${point}" \
    >"$WORK/zero.der"
"$OPENSSL" pkey -in "$WORK/zero.der" -inform DER -out "$WORK/zero.pem"
for args in "-text -noout" "-outform DER" ""; do
    read -r -a extra <<<"$args"
    same "leading zero ${args:-(none)}" -in "$WORK/zero.pem" \
        ${extra[@]+"${extra[@]}"}
done

# The same key without its public key, which ECPrivateKey makes optional:
# OpenSSL writes it back without it, and computes it to print or export.
"$OPENSSL" pkey -in "$WORK/zero0.der" -inform DER -out "$WORK/nopub.pem"
for args in "" "-outform DER" "-text -noout" "-pubout" "-check -noout"; do
    read -r -a extra <<<"$args"
    same "no public key ${args:-(none)}" -in "$WORK/nopub.pem" \
        ${extra[@]+"${extra[@]}"}
done
same "no public key, SEC 1 DER" -in "$WORK/zero0.der" -inform DER

interop_summary pkey-interop "$pass" "$fail"
