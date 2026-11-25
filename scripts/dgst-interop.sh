#!/usr/bin/env bash
#
# Differential tests of `dgst` (and its shortcuts `sha1` to `sha512`)
# against a real OpenSSL:
#
# - every digest, on an empty file, "abc", and 100000 random bytes, in each
#   output form (-hex, -c, -r, -binary), from files and standard input,
#   with HMAC under keys shorter and longer than the hash block;
# - for every key of tests/fixtures/keys/keypairs.txt and every digest,
#   signatures in both directions: baldssl signs and OpenSSL verifies, and
#   OpenSSL signs and baldssl verifies, with -verify and -prverify, on the
#   message and on a changed one. ECDSA signatures differ (OpenSSL draws
#   its nonces at random, baldssl follows RFC 6979), so they are checked by
#   verification; Ed25519 signatures are compared byte for byte;
# - the errors: malformed signatures, keys that do not load, misused
#   options, and the -signature cases OpenSSL mishandles.
#
# baldssl and OpenSSL must give the same exit code, the same standard
# output, and the same first two lines of standard error that are not
# OpenSSL's error stack. OpenSSL 3.0 cannot sign with Ed25519 in dgst;
# baldssl's 3.0 profile refuses it the same way.
#
# Usage:
#   scripts/dgst-interop.sh <path/to/openssl> <path/to/baldssl>
#
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
    echo "usage: $0 <openssl> <baldssl>" >&2
    exit 2
fi
absolute() {
    if [[ "$1" == */* ]]; then
        echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
    else
        echo "$1"
    fi
}
OPENSSL=$(absolute "$1")
BALDSSL=$(absolute "$2")
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/baldssl-dgst.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
OPENSSL_VERSION=$("$OPENSSL" version | awk '{print $2}')
case "$OPENSSL_VERSION" in
    3.0.*) BALDSSL_OPENSSL_COMPAT=3.0 ;;
    3.6.*) BALDSSL_OPENSSL_COMPAT=3.6 ;;
    *) BALDSSL_OPENSSL_COMPAT=${OPENSSL_VERSION%%.*} ;;
esac
export BALDSSL_OPENSSL_COMPAT
pass=0
fail=0
cd "$WORK"

# The report on standard error: its first two lines, without OpenSSL's
# error stack.
report() { grep -v ':error:' "$1" | head -2 || true; }

# same <stdin file> <arguments...>: the same exit code, output and report.
same() {
    local input=$1 ro=0 rb=0
    shift
    "$OPENSSL" "$@" <"$input" >o.out 2>o.err || ro=$?
    "$BALDSSL" "$@" <"$input" >b.out 2>b.err || rb=$?
    if [[ "$ro" -eq "$rb" ]] && cmp -s o.out b.out &&
        [[ "$(report o.err)" == "$(report b.err)" ]]; then
        pass=$((pass + 1))
    else
        echo "FAIL [$*]: exit $ro/$rb; $(report o.err | tr '\n' '|') vs" \
            "$(report b.err | tr '\n' '|')"
        fail=$((fail + 1))
    fi
}

# check <description> <command...>: the command succeeds.
check() {
    local what=$1
    shift
    if "$@" >/dev/null 2>&1; then
        pass=$((pass + 1))
    else
        echo "FAIL $what"
        fail=$((fail + 1))
    fi
}

# refuse <description> <command...>: the command fails.
refuse() {
    local what=$1
    shift
    if "$@" >/dev/null 2>&1; then
        echo "FAIL $what (accepted)"
        fail=$((fail + 1))
    else
        pass=$((pass + 1))
    fi
}

unhex() { perl -e 'print pack("H*", shift)' "$1"; }

: >empty.txt
printf 'abc' >abc.txt
head -c 100000 /dev/urandom >random.bin
printf 'abc!' >other.txt

# 1. Digests and MACs.
long_key=$(printf 'k%.0s' $(seq 1 200))
for d in sha1 sha224 sha256 sha384 sha512; do
    for f in empty.txt abc.txt random.bin; do
        same "$f" dgst "-$d" "$f"
        same "$f" dgst "-$d" -c "$f"
        same "$f" dgst "-$d" -r "$f"
        same "$f" dgst "-$d" -binary "$f"
        same "$f" dgst "-$d"
        same "$f" "$d" "$f"
        same "$f" dgst "-$d" -hmac secret "$f"
        same "$f" dgst "-$d" -hmac "$long_key" -r "$f"
        same "$f" dgst "-$d" -hmac secret
    done
    same abc.txt dgst "-$d" abc.txt empty.txt random.bin
done
same abc.txt dgst abc.txt
same abc.txt dgst -hmac secret abc.txt
# The key is the argument's bytes, not text: a byte that is not UTF-8 is
# kept as it is, not replaced.
same abc.txt dgst -hmac "$(printf 'k\377e')" abc.txt
same abc.txt dgst abc.txt missing.txt abc.txt
same abc.txt dgst abc.txt -sha1
same abc.txt dgst -- abc.txt
same abc.txt dgst -sha256 -out out.txt abc.txt
cp out.txt o-out.txt
"$BALDSSL" dgst -sha256 -out out.txt abc.txt
check "dgst -out" cmp out.txt o-out.txt

# 2. Signatures, with every fixture key.
n=0
while read -r curve _ _ pkcs8; do
    n=$((n + 1))
    unhex "$pkcs8" >key.der
    "$OPENSSL" pkey -inform DER -in key.der -out key.pem
    "$OPENSSL" pkey -in key.pem -pubout -out pub.pem
    if [[ "$curve" == ED25519 ]]; then
        digests=("")
    else
        digests=(-sha1 -sha224 -sha256 -sha384 -sha512 "")
    fi
    for d in "${digests[@]}"; do
        dd=()
        [[ -n "$d" ]] && dd=("$d")
        label="key $n $curve ${d:-default}"
        if [[ "$curve" == ED25519 && "$BALDSSL_OPENSSL_COMPAT" == 3.0 ]]; then
            same abc.txt dgst -sign key.pem abc.txt
            same abc.txt dgst -verify pub.pem -signature key.der abc.txt
            continue
        fi
        "$BALDSSL" dgst ${dd[@]+"${dd[@]}"} -sign key.pem -out b.sig abc.txt
        check "$label: OpenSSL verifies baldssl's signature" \
            "$OPENSSL" dgst ${dd[@]+"${dd[@]}"} -verify pub.pem \
            -signature b.sig abc.txt
        "$OPENSSL" dgst ${dd[@]+"${dd[@]}"} -sign key.pem -out o.sig abc.txt
        same abc.txt dgst ${dd[@]+"${dd[@]}"} -verify pub.pem \
            -signature o.sig abc.txt
        same abc.txt dgst ${dd[@]+"${dd[@]}"} -prverify key.pem \
            -signature o.sig abc.txt
        same abc.txt dgst ${dd[@]+"${dd[@]}"} -verify pub.pem \
            -signature o.sig other.txt
        same abc.txt dgst ${dd[@]+"${dd[@]}"} -verify pub.pem \
            -signature b.sig other.txt
        if [[ "$curve" == ED25519 ]]; then
            check "$label: the signature is OpenSSL's" cmp b.sig o.sig
            same abc.txt dgst -sign key.pem -hex abc.txt
            same abc.txt dgst -sign key.pem -hex -c
            same abc.txt dgst -sign key.pem -sha256 abc.txt
        else
            "$BALDSSL" dgst ${dd[@]+"${dd[@]}"} -sign key.pem -hex abc.txt \
                >b.hex
            check "$label: -hex label" grep -q '^EC-SHA[0-9-]*(abc.txt)= ' b.hex
        fi
    done
    same abc.txt dgst -sign key.pem -verify pub.pem abc.txt
    same abc.txt dgst -sign key.pem abc.txt abc.txt
    same abc.txt dgst -verify key.pem -signature b.sig abc.txt
    same abc.txt dgst -sign key.pem -signature b.sig abc.txt
    same abc.txt dgst -sign pub.pem abc.txt
    same abc.txt dgst -keyform DER -sign key.der -verify pub.pem \
        -signature b.sig abc.txt
done < <(grep -v '^#' "$ROOT/tests/fixtures/keys/keypairs.txt")
refuse "key file count" test "$n" -eq 0

# 3. Malformed signatures and other errors, on a P-256 key.
unhex "$(grep -v '^#' "$ROOT/tests/fixtures/keys/keypairs.txt" |
    awk '$1 == "P-256" {print $4; exit}')" >ec.der
"$OPENSSL" pkey -inform DER -in ec.der -out ec.pem
"$OPENSSL" pkey -in ec.pem -pubout -out ecpub.pem
"$OPENSSL" dgst -sign ec.pem -out good.sig abc.txt
head -c 10 /dev/urandom >junk.sig
head -c 20 good.sig >trunc.sig
{ cat good.sig; printf '\0'; } >trail.sig
: >empty.sig
perl -e 'local $/; my $d = <STDIN>; print "\x30\x81", substr($d, 1)' \
    <good.sig >ber.sig
unhex 3006020100020101 >zero.sig
unhex 30060201ff020101 >neg.sig
for s in junk trunc trail ber zero neg empty missing; do
    same abc.txt dgst -verify ecpub.pem -signature "$s.sig" abc.txt
done
same abc.txt dgst -verify ecpub.pem abc.txt
same abc.txt dgst -verify abc.txt -signature good.sig abc.txt
same abc.txt dgst -verify missing.pem -signature good.sig abc.txt
same abc.txt dgst -sign abc.txt abc.txt
same abc.txt dgst -sign missing.pem abc.txt
same abc.txt dgst -keyform XYZ -sign ec.pem abc.txt
same abc.txt dgst -hmac k -sign ec.pem abc.txt
same abc.txt dgst -hmac k -signature good.sig abc.txt
same abc.txt dgst -hmac k -signature missing.sig abc.txt
same abc.txt dgst -sha256 -xoflen 3 abc.txt
same abc.txt sha256 -sign ec.pem abc.txt abc.txt

echo "dgst-interop: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
