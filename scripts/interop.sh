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

# shellcheck source=scripts/interop-profile.sh
source "$ROOT/scripts/interop-profile.sh"
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
        interop_pass "$label"
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
        interop_pass "$base/reverse"
    else
        echo "FAIL $base/reverse: OpenSSL does not read back baldssl output"
        fail=$((fail + 1))
    fi
    if [[ "$cert" == "$WORK"/* ]]; then
        if "$OPENSSL" verify -CAfile "$WORK/b.pem" "$WORK/b.pem" >/dev/null 2>&1 \
            || "$OPENSSL" verify -partial_chain -CAfile "$WORK/b.pem" \
                "$WORK/b.pem" >/dev/null 2>&1; then
            interop_pass "$base/verify"
        else
            echo "FAIL $base/verify: OpenSSL rejects baldssl's re-encoding"
            fail=$((fail + 1))
        fi
    fi
done

# genpkey: OpenSSL must accept every key baldssl generates, the key must
# have exactly the structure of one OpenSSL generates (the random bytes
# masked out of the asn1parse listing), and its file the same mode
# (readable by its owner only, as bio_open_owner creates it).
mode() { perl -e 'printf "%o", (stat shift)[2] & 0777' "$1"; }
structure() {
    "$OPENSSL" asn1parse -in "$1" -i | sed -E 's/\[HEX DUMP\]:[0-9A-F]+//'
}
structure_der() {
    "$OPENSSL" asn1parse -inform DER -in "$1" -i |
        sed -E 's/\[HEX DUMP\]:[0-9A-F]+//'
}
for spec in "EC ec_paramgen_curve:P-256" "EC ec_paramgen_curve:P-384" \
    "EC ec_paramgen_curve:P-521" "ED25519"; do
    read -r alg opt <<<"$spec"
    args=(-algorithm "$alg")
    [[ -n "$opt" ]] && args+=(-pkeyopt "$opt")
    label="genpkey/${opt:-$alg}"
    # A file that exists keeps its mode, so each run starts without one.
    rm -f "$WORK/b-key.pem" "$WORK/o-key.pem"
    if ! "$BALDSSL" genpkey "${args[@]}" -out "$WORK/b-key.pem"; then
        echo "FAIL $label: baldssl genpkey failed"
        fail=$((fail + 1))
        continue
    fi
    "$OPENSSL" genpkey "${args[@]}" -out "$WORK/o-key.pem"
    if [[ "$(mode "$WORK/b-key.pem")" != "$(mode "$WORK/o-key.pem")" ]]; then
        echo "FAIL $label: key file mode $(mode "$WORK/b-key.pem")"
        fail=$((fail + 1))
    elif ! "$OPENSSL" pkey -in "$WORK/b-key.pem" -noout -check >/dev/null; then
        echo "FAIL $label: OpenSSL rejects the key"
        fail=$((fail + 1))
    elif ! cmp -s <(structure "$WORK/b-key.pem") \
        <(structure "$WORK/o-key.pem"); then
        echo "FAIL $label: structure differs from OpenSSL's"
        diff <(structure "$WORK/o-key.pem") <(structure "$WORK/b-key.pem") || true
        fail=$((fail + 1))
    else
        interop_pass "$label"
    fi
    # In DER, the key has the structure of OpenSSL's: the traditional form
    # or PKCS#8, by release line.
    "$BALDSSL" genpkey "${args[@]}" -outform DER -out "$WORK/b-key.der"
    "$OPENSSL" genpkey "${args[@]}" -outform DER -out "$WORK/o-key.der"
    if cmp -s <(structure_der "$WORK/b-key.der") \
        <(structure_der "$WORK/o-key.der"); then
        interop_pass "$label -outform DER"
    else
        echo "FAIL $label -outform DER: structure differs from OpenSSL's"
        diff <(structure_der "$WORK/o-key.der") \
            <(structure_der "$WORK/b-key.der") || true
        fail=$((fail + 1))
    fi
    # -text follows the key with its text: what OpenSSL's pkey -text prints
    # of the key written.
    "$BALDSSL" genpkey "${args[@]}" -text >"$WORK/b-text.pem"
    if cmp -s "$WORK/b-text.pem" \
        <("$OPENSSL" pkey -in "$WORK/b-text.pem" -text); then
        interop_pass "$label -text"
    else
        echo "FAIL $label -text: differs from OpenSSL's pkey -text"
        diff <("$OPENSSL" pkey -in "$WORK/b-text.pem" -text) \
            "$WORK/b-text.pem" || true
        fail=$((fail + 1))
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

# Option errors, in every command: the same standard error (without
# OpenSSL's error stack) and the same exit code. OpenSSL 3.0's x509 does
# not check an unknown option it reads as a digest, so that case is left
# out for 3.0.
usage_same() {
    # usage_same <label> <command> <args...>
    local label=$1 o_rc=0 b_rc=0
    shift
    "$OPENSSL" "$@" </dev/null >/dev/null 2>"$WORK/o.err" || o_rc=$?
    "$BALDSSL" "$@" </dev/null >/dev/null 2>"$WORK/b.err" || b_rc=$?
    grep -Ev '^[0-9A-F]+:error:' "$WORK/o.err" >"$WORK/o2.err" || true
    if [[ "$o_rc" -eq "$b_rc" ]] && cmp -s "$WORK/o2.err" "$WORK/b.err"; then
        interop_pass "$label"
    else
        echo "FAIL $label: exit $o_rc/$b_rc"
        diff "$WORK/o2.err" "$WORK/b.err" || true
        fail=$((fail + 1))
    fi
}
for cmd in x509 req pkey genpkey dgst sha256 verify; do
    for args in "-nosuch" "-in" "-noout=1" "-text=1" "-a -b" "-nosuch -in"; do
        if [[ "$cmd $args" == "x509 -nosuch" || "$cmd $args" == "x509 -a -b" ]] &&
            [[ "$OPENSSL_VERSION" == 3.0.* ]]; then
            continue
        fi
        read -r -a argv <<<"$args"
        usage_same "usage/$cmd $args" "$cmd" "${argv[@]}"
    done
done
# Operands where none are taken, and genpkey's cipher, read once it has an
# algorithm.
for cmd in x509 req pkey genpkey; do
    usage_same "usage/$cmd extra" "$cmd" extra
    usage_same "usage/$cmd -nosuch extra" "$cmd" -nosuch extra
done
usage_same "usage/genpkey -algorithm ed25519 -nosuch" genpkey \
    -algorithm ed25519 -nosuch
usage_same "usage/genpkey -algorithm ed25519 -a -b" genpkey \
    -algorithm ed25519 -a -b
usage_same "usage/genpkey" genpkey
# A digest is an undeclared option too: from OpenSSL 3.2 a second one is
# refused, and 3.0 reads the last.
usage_same "usage/x509 two digests" x509 -in "${CERTS[0]}" -noout \
    -fingerprint -sha256 -sha1
usage_same "usage/dgst two digests" dgst -sha256 -sha1 "${CERTS[0]}"
usage_same "usage/dgst digest then unknown" dgst -sha256 -nosuch "${CERTS[0]}"

interop_summary interop "$pass" "$fail"
