#!/usr/bin/env bash
#
# Checks that two OpenSSL builds write the same PKCS#8 bytes for every key
# of tests/fixtures/keys/keypairs.txt: each build reads the key (PKCS#8 DER)
# and writes it again with `openssl pkey` (PKCS#8 PEM, its default), and the
# DER inside must be byte for byte the fixture's. This is the evidence for
# the claim, in baldssl-pkey's documentation, that the encoding is the same
# in both releases.
#
# Usage:
#   scripts/pkcs8-agreement.sh <openssl-a> <openssl-b>
#

set -euo pipefail

if [[ "$#" -ne 2 ]]; then
    echo "usage: $0 <openssl-a> <openssl-b>" >&2
    exit 2
fi
FIXTURES="$(dirname "$0")/../tests/fixtures/keys/keypairs.txt"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/baldssl-pkcs8.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

fail=0
count=0
while read -r name _private _public der; do
    [[ "$name" == "#"* || -z "$name" ]] && continue
    printf '%s' "$der" | xxd -r -p >"$WORK/key.der"
    for openssl in "$1" "$2"; do
        "$openssl" pkey -inform DER -in "$WORK/key.der" -out "$WORK/out.pem"
        "$openssl" asn1parse -in "$WORK/out.pem" -noout -out "$WORK/out.der" \
            >/dev/null
        if ! cmp -s "$WORK/key.der" "$WORK/out.der"; then
            echo "DIFF $name: $("$openssl" version)"
            fail=$((fail + 1))
        fi
    done
    count=$((count + 1))
done <"$FIXTURES"

echo "pkcs8-agreement: $count keys, $fail differences"
[[ "$fail" -eq 0 ]]
