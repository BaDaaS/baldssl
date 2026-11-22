#!/usr/bin/env bash
#
# Differential tests of `req` against a real OpenSSL, both directions, for
# every key of tests/fixtures/keys/keypairs.txt and a few subjects:
#
# - OpenSSL verifies the request baldssl writes (`openssl req -verify`),
#   and baldssl verifies the one OpenSSL writes;
# - Ed25519 requests are identical (Ed25519 is deterministic); ECDSA ones
#   have the same subject and public key (OpenSSL's nonces are random);
# - reading and converting OpenSSL's request (PEM, DER, -noout) prints what
#   OpenSSL prints;
# - a request with a changed byte fails -verify in both. OpenSSL 3.0 prints
#   "verify failure" but exits 0 there (later releases exit 1), so with
#   3.0 OpenSSL's refusal is read from its message. baldssl exits 1 under
#   every profile: a script that trusts the exit code must not accept a
#   forged request.
#
# Usage:
#   scripts/req-interop.sh <path/to/openssl> <path/to/baldssl>
#
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
    echo "usage: $0 <openssl> <baldssl>" >&2
    exit 2
fi
OPENSSL=$1
BALDSSL=$2
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/baldssl-req.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
OPENSSL_VERSION=$("$OPENSSL" version | awk '{print $2}')
pass=0
fail=0

check() {
    # check <label> <command...>: the command must succeed.
    local label=$1
    shift
    if "$@" >"$WORK/out" 2>&1; then
        pass=$((pass + 1))
    else
        echo "FAIL $label: $(head -3 "$WORK/out")"
        fail=$((fail + 1))
    fi
}

refuse() {
    # refuse <label> <command...>: the command must fail.
    local label=$1
    shift
    if "$@" >/dev/null 2>&1; then
        echo "FAIL $label: accepted"
        fail=$((fail + 1))
    else
        pass=$((pass + 1))
    fi
}

same() {
    # same <label> <file> <file>
    if cmp -s "$2" "$3"; then
        pass=$((pass + 1))
    else
        echo "FAIL $1: outputs differ"
        fail=$((fail + 1))
    fi
}

unhex() { perl -e 'print pack("H*", shift)' "$1"; }

subjects=("/CN=test.example" "/C=BE/O=Org/CN=x" "/CN=a+O=b/emailAddress=x@y.example")
n=0
while read -r curve _private _public pkcs8; do
    n=$((n + 1))
    key="$WORK/key$n.der"
    unhex "$pkcs8" >"$key"
    for subj in "${subjects[@]}"; do
        label="$curve $n $subj"
        "$BALDSSL" req -new -key "$key" -keyform DER -subj "$subj" \
            -out "$WORK/b.pem"
        "$OPENSSL" req -new -key "$key" -keyform DER -subj "$subj" \
            -out "$WORK/o.pem" 2>/dev/null
        check "$label: OpenSSL verifies baldssl's" \
            "$OPENSSL" req -in "$WORK/b.pem" -verify -noout
        check "$label: baldssl verifies OpenSSL's" \
            "$BALDSSL" req -in "$WORK/o.pem" -verify -noout
        if [[ "$curve" == "ED25519" ]]; then
            same "$label: identical" "$WORK/b.pem" "$WORK/o.pem"
            # Ed25519 fixes its hash: a digest option changes nothing.
            "$BALDSSL" req -new -key "$key" -keyform DER -subj "$subj" \
                -sha384 -out "$WORK/b.pem"
            same "$label: -sha384 ignored" "$WORK/b.pem" "$WORK/o.pem"
        else
            "$OPENSSL" req -in "$WORK/b.pem" -noout -subject -pubkey \
                >"$WORK/b.txt"
            "$OPENSSL" req -in "$WORK/o.pem" -noout -subject -pubkey \
                >"$WORK/o.txt"
            same "$label: subject and key" "$WORK/b.txt" "$WORK/o.txt"
        fi
        for args in "" "-outform DER" "-noout"; do
            # shellcheck disable=SC2086 # args is a word list by design
            "$OPENSSL" req -in "$WORK/o.pem" $args >"$WORK/o.out"
            # shellcheck disable=SC2086
            "$BALDSSL" req -in "$WORK/o.pem" $args >"$WORK/b.out"
            same "$label: req ${args:-(PEM)}" "$WORK/o.out" "$WORK/b.out"
        done
        "$OPENSSL" req -in "$WORK/o.pem" -outform DER -out "$WORK/o.der"
        "$OPENSSL" req -in "$WORK/o.der" -inform DER >"$WORK/o.out"
        "$BALDSSL" req -in "$WORK/o.der" -inform DER >"$WORK/b.out"
        same "$label: -inform DER" "$WORK/o.out" "$WORK/b.out"
        # A changed last byte: the signature no longer verifies.
        perl -e 'local $/; my $d = <STDIN>; substr($d, -1, 1) ^= "\x01";
            print $d' <"$WORK/o.der" >"$WORK/bad.der"
        if [[ "$OPENSSL_VERSION" == 3.0.* ]]; then
            if "$OPENSSL" req -in "$WORK/bad.der" -inform DER -verify \
                -noout 2>&1 | grep -q "verify failure"; then
                pass=$((pass + 1))
            else
                echo "FAIL $label: OpenSSL 3.0 does not report the failure"
                fail=$((fail + 1))
            fi
        else
            refuse "$label: OpenSSL refuses a changed request" \
                "$OPENSSL" req -in "$WORK/bad.der" -inform DER -verify -noout
        fi
        refuse "$label: baldssl refuses a changed request" \
            "$BALDSSL" req -in "$WORK/bad.der" -inform DER -verify -noout
    done
done < <(grep -v '^#' "$ROOT/tests/fixtures/keys/keypairs.txt")

echo "req-interop: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
