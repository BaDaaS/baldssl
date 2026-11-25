#!/usr/bin/env bash
# Differential interop test between an OpenSSL binary and baldssl.
#
# 1. Generates fresh certificates with OpenSSL (scripts/gen-certs.sh).
# 2. Runs `openssl x509 <args>` and `baldssl x509 <args>` on every
#    certificate (generated ones plus tests/fixtures/certs) for every argument
#    set in tests/fixtures/cases.txt, and requires identical stdout and the
#    same success/failure.
# 3. Reverse direction: re-encodes each certificate with baldssl
#    (-outform DER and PEM) and requires OpenSSL to read it back to the same
#    DER, and `openssl verify` to accept the re-encoded self-signed
#    certificate.
# 4. Error paths: missing file, garbage input, unknown option must fail in
#    both.
#
# Usage: scripts/interop.sh <path/to/openssl> <path/to/baldssl>
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <openssl> <baldssl>" >&2
    exit 2
fi
OPENSSL=$1
BALDSSL=$2
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CASES="$ROOT/tests/fixtures/cases.txt"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/baldssl-interop.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0

# Imitate the release line of the OpenSSL under test (see README, "OpenSSL
# compatibility profiles").
OPENSSL_VERSION=$("$OPENSSL" version | awk '{print $2}')
case "$OPENSSL_VERSION" in
    3.0.*) BALDSSL_OPENSSL_COMPAT=3.0 ;;
    3.6.*) BALDSSL_OPENSSL_COMPAT=3.6 ;;
    *) BALDSSL_OPENSSL_COMPAT=${OPENSSL_VERSION%%.*} ;;
esac
export BALDSSL_OPENSSL_COMPAT
echo "OpenSSL: $("$OPENSSL" version) (profile $BALDSSL_OPENSSL_COMPAT)"
echo "baldssl: $("$BALDSSL" version)"

"$ROOT/scripts/gen-certs.sh" "$OPENSSL" "$WORK" || fail=$((fail + 1))

CERTS=()
for f in "$WORK"/*.crt "$ROOT"/tests/fixtures/certs/*.crt; do
    [ -e "$f" ] && CERTS+=("$f")
done

compare() {
    # compare <label> <args...>: same stdout and same success in both.
    local label=$1
    shift
    local o_rc=0 b_rc=0
    "$OPENSSL" x509 "$@" >"$WORK/o.out" 2>/dev/null || o_rc=$?
    "$BALDSSL" x509 "$@" >"$WORK/b.out" 2>"$WORK/b.err" || b_rc=$?
    if [ "$o_rc" -eq 0 ] && [ "$b_rc" -ne 0 ]; then
        echo "FAIL $label: baldssl failed (exit $b_rc): $(cat "$WORK/b.err")"
        fail=$((fail + 1))
    elif [ "$o_rc" -ne 0 ] && [ "$b_rc" -eq 0 ]; then
        echo "FAIL $label: openssl failed (exit $o_rc), baldssl succeeded"
        fail=$((fail + 1))
    elif ! cmp -s "$WORK/o.out" "$WORK/b.out"; then
        echo "FAIL $label: output differs"
        diff "$WORK/o.out" "$WORK/b.out" | head -20 || true
        fail=$((fail + 1))
    else
        pass=$((pass + 1))
    fi
}

for cert in "${CERTS[@]}"; do
    base=$(basename "$cert" .crt)
    der="$WORK/$base.der"
    "$OPENSSL" x509 -in "$cert" -outform DER -out "$der"
    while IFS='|' read -r case args; do
        case "$case" in '' | '#'*) continue ;; esac
        # shellcheck disable=SC2086 # args is a word list by design
        compare "$base/$case" -in "$cert" $args
    done <"$CASES"
    compare "$base/der-explicit" -in "$der" -inform DER -noout -text
    compare "$base/der-detect" -in "$der" -noout -text
    compare "$base/to-der" -in "$cert" -outform DER

    # Reverse direction: OpenSSL must accept what baldssl writes.
    "$BALDSSL" x509 -in "$cert" -outform DER -out "$WORK/b.der"
    "$BALDSSL" x509 -in "$der" -out "$WORK/b.pem"
    if cmp -s "$der" "$WORK/b.der" &&
        "$OPENSSL" x509 -in "$WORK/b.der" -inform DER -outform DER \
            -out "$WORK/rt.der" && cmp -s "$der" "$WORK/rt.der" &&
        "$OPENSSL" x509 -in "$WORK/b.pem" -outform DER -out "$WORK/rt2.der" &&
        cmp -s "$der" "$WORK/rt2.der"; then
        pass=$((pass + 1))
    else
        echo "FAIL $base/reverse: OpenSSL does not read back baldssl output"
        fail=$((fail + 1))
    fi
    if [[ "$cert" == "$WORK"/* ]]; then
        if "$OPENSSL" verify -CAfile "$WORK/b.pem" "$WORK/b.pem" >/dev/null 2>&1 \
            || "$OPENSSL" verify -partial_chain -CAfile "$WORK/b.pem" \
                "$WORK/b.pem" >/dev/null 2>&1; then
            pass=$((pass + 1))
        else
            echo "FAIL $base/verify: OpenSSL rejects baldssl's re-encoding"
            fail=$((fail + 1))
        fi
    fi
done

# genpkey: OpenSSL must accept every key baldssl generates, and the key
# must have exactly the structure of one OpenSSL generates (the random
# bytes masked out of the asn1parse listing).
structure() {
    "$OPENSSL" asn1parse -in "$1" -i | sed -E 's/\[HEX DUMP\]:[0-9A-F]+//'
}
for spec in "EC ec_paramgen_curve:P-256" "EC ec_paramgen_curve:P-384" \
    "EC ec_paramgen_curve:P-521" "ED25519"; do
    read -r alg opt <<<"$spec"
    args=(-algorithm "$alg")
    [[ -n "$opt" ]] && args+=(-pkeyopt "$opt")
    label="genpkey/${opt:-$alg}"
    if ! "$BALDSSL" genpkey "${args[@]}" -out "$WORK/b-key.pem"; then
        echo "FAIL $label: baldssl genpkey failed"
        fail=$((fail + 1))
        continue
    fi
    "$OPENSSL" genpkey "${args[@]}" -out "$WORK/o-key.pem"
    if ! "$OPENSSL" pkey -in "$WORK/b-key.pem" -noout -check >/dev/null; then
        echo "FAIL $label: OpenSSL rejects the key"
        fail=$((fail + 1))
    elif ! cmp -s <(structure "$WORK/b-key.pem") \
        <(structure "$WORK/o-key.pem"); then
        echo "FAIL $label: structure differs from OpenSSL's"
        diff <(structure "$WORK/o-key.pem") <(structure "$WORK/b-key.pem") || true
        fail=$((fail + 1))
    else
        pass=$((pass + 1))
    fi
done

# Error paths must fail in both (exit codes may differ: see README).
head -c 300 /dev/urandom >"$WORK/garbage.bin"
printf -- '-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n' \
    >"$WORK/badpem.pem"
compare "err/missing" -in "$WORK/does-not-exist.pem" -noout
compare "err/garbage" -in "$WORK/garbage.bin" -noout
compare "err/badpem" -in "$WORK/badpem.pem" -noout
# OpenSSL 3.0's x509 ignores unknown options and exits 0; baldssl rejects
# them like 3.5 and later, so the check is skipped for 3.0.
case "$OPENSSL_VERSION" in
    3.0.*) echo "skip err/unknown-option: OpenSSL 3.0 ignores unknown options" ;;
    *) compare "err/unknown-option" -in "${CERTS[0]}" -no-such-option ;;
esac
compare "err/extra-arg" -in "${CERTS[0]}" extra
compare "err/missing-value" -in

echo "interop: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
