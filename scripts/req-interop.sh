#!/usr/bin/env bash
#
# Differential tests of `req` against a real OpenSSL, both directions, for
# every key of tests/fixtures/keys/keypairs.txt and a few subjects:
#
# - OpenSSL verifies the request baldssl writes (`openssl req -verify`),
#   and baldssl verifies the one OpenSSL writes;
# - Ed25519 requests are identical (Ed25519 is deterministic); ECDSA ones
#   have the same subject and public key (OpenSSL's nonces are random);
# - reading, converting and printing OpenSSL's request (PEM, DER, -noout,
#   -text) prints what OpenSSL prints;
# - self-signed certificates (-x509) verify as their own CA in OpenSSL,
#   and match OpenSSL's for a fixed serial and validity;
# - -newkey: requests on a generated key verify in OpenSSL, the key is
#   the request's, standard error is OpenSSL's, and the key file is
#   readable by its owner only;
# - -addext: requests and -x509 certificates identical to OpenSSL's for an
#   Ed25519 key, and the same refusals;
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
# Absolute paths, so the programs still run from another directory.
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
WORK=$(mktemp -d "${TMPDIR:-/tmp}/baldssl-req.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=scripts/interop-profile.sh
source "$ROOT/scripts/interop-profile.sh"
pass=0
fail=0

check() {
    # check <label> <command...>: the command must succeed.
    local label=$1
    shift
    if "$@" >"$WORK/out" 2>&1; then
        interop_pass "$label"
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
        interop_pass "$label (refused)"
    fi
}

same() {
    # same <label> <file> <file>
    if cmp -s "$2" "$3"; then
        interop_pass "$1"
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
        for args in "" "-outform DER" "-noout" "-text" "-noout -text"; do
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
                interop_pass "$label"
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
        # Self-signed certificates: OpenSSL verifies baldssl's as its own
        # CA; with a fixed serial and validity, Ed25519 ones are identical
        # and ECDSA ones print the same fields. OpenSSL 3.0's req has no
        # -not_before, so with it only the verification runs.
        "$BALDSSL" req -x509 -key "$key" -keyform DER -subj "$subj" \
            -out "$WORK/bc.pem"
        check "$label: OpenSSL verifies baldssl's certificate" \
            "$OPENSSL" verify -CAfile "$WORK/bc.pem" "$WORK/bc.pem"
        if [[ "$OPENSSL_VERSION" != 3.0.* ]]; then
            fixed=(-set_serial 0x0102 -not_before 20261122000000Z
                -not_after 20510101000000Z)
            "$BALDSSL" req -x509 -key "$key" -keyform DER -subj "$subj" \
                "${fixed[@]}" -out "$WORK/bc.pem"
            "$OPENSSL" req -x509 -key "$key" -keyform DER -subj "$subj" \
                "${fixed[@]}" -out "$WORK/oc.pem" 2>/dev/null
            if [[ "$curve" == "ED25519" ]]; then
                same "$label: identical certificates" "$WORK/bc.pem" \
                    "$WORK/oc.pem"
                "$BALDSSL" req -x509 -key "$key" -keyform DER \
                    -subj "$subj" "${fixed[@]}" -text -noout >"$WORK/b.txt"
                "$OPENSSL" req -x509 -key "$key" -keyform DER \
                    -subj "$subj" "${fixed[@]}" -text -noout \
                    >"$WORK/o.txt" 2>/dev/null
                same "$label: -x509 -text" "$WORK/o.txt" "$WORK/b.txt"
            else
                extensions="subjectKeyIdentifier,authorityKeyIdentifier"
                extensions+=",basicConstraints"
                fields=(-noout -subject -issuer -serial -dates -pubkey
                    -ext "$extensions")
                "$OPENSSL" x509 -in "$WORK/bc.pem" "${fields[@]}" \
                    >"$WORK/b.txt"
                "$OPENSSL" x509 -in "$WORK/oc.pem" "${fields[@]}" \
                    >"$WORK/o.txt"
                same "$label: certificate fields" "$WORK/b.txt" "$WORK/o.txt"
            fi
        fi
    done
done < <(grep -v '^#' "$ROOT/tests/fixtures/keys/keypairs.txt")

# -addext: with an Ed25519 key a request is deterministic, so baldssl's is
# OpenSSL's byte for byte, for every line of a corpus (spacing quirks of
# OpenSSL's list parser included); with -x509, an -addext overrides v3_ca's
# extension of its kind in place. Both refuse a duplicate name, an unknown
# key usage and an unknown extension.
ed_key=$(grep '^ED25519' "$ROOT/tests/fixtures/keys/keypairs.txt" | head -1 |
    awk '{print $4}')
unhex "$ed_key" >"$WORK/ed.der"
addexts=("subjectAltName=DNS:a.example,DNS:b.example,IP:10.0.0.1,IP:2001:db8::1"
    "subjectAltName=email:x@y.example, URI:https://u.example.com/p?q"
    "subjectAltName = DNS:a , DNS:bc ,DNS: d"
    "keyUsage=critical,digitalSignature,keyEncipherment"
    "keyUsage=keyCertSign, cRLSign, decipherOnly"
    "keyUsage=Digital Signature, keyCertSign"
    "extendedKeyUsage=serverAuth,clientAuth,1.3.6.1.5.5.7.3.3"
    "basicConstraints=critical,CA:TRUE,pathlen:2"
    "basicConstraints=CA:FALSE")
for line in "${addexts[@]}"; do
    for who in OPENSSL BALDSSL; do
        "${!who}" req -new -key "$WORK/ed.der" -keyform DER -subj /CN=x \
            -addext "$line" -outform DER -out "$WORK/$who.der" 2>/dev/null
    done
    same "-addext $line: identical" "$WORK/OPENSSL.der" "$WORK/BALDSSL.der"
    "$OPENSSL" req -in "$WORK/OPENSSL.der" -inform DER -noout -text \
        >"$WORK/o.txt"
    "$BALDSSL" req -in "$WORK/OPENSSL.der" -inform DER -noout -text \
        >"$WORK/b.txt"
    same "-addext $line: -text" "$WORK/o.txt" "$WORK/b.txt"
done
if [[ "$OPENSSL_VERSION" != 3.0.* ]]; then
    for who in OPENSSL BALDSSL; do
        "${!who}" req -x509 -key "$WORK/ed.der" -keyform DER -subj /CN=x \
            -set_serial 7 -not_before 20261122000000Z \
            -not_after 20271122000000Z -addext "basicConstraints=CA:FALSE" \
            -addext "subjectAltName=DNS:x.example" -outform DER \
            -out "$WORK/$who.der" 2>/dev/null
    done
    same "-x509 -addext: identical" "$WORK/OPENSSL.der" "$WORK/BALDSSL.der"
fi
for bad in "keyUsage=badName" "fooBar=x" "keyUsage=critical ,digitalSignature" \
    "X509v3 Key Usage=digitalSignature"; do
    for who in OPENSSL BALDSSL; do
        refuse "$who refuses -addext $bad" "${!who}" req -new \
            -key "$WORK/ed.der" -keyform DER -subj /CN=x -addext "$bad" \
            -out "$WORK/x.csr"
    done
done
for who in OPENSSL BALDSSL; do
    refuse "$who refuses a duplicate -addext" "${!who}" req -new \
        -key "$WORK/ed.der" -keyform DER -subj /CN=x \
        -addext keyUsage=digitalSignature -addext keyUsage=cRLSign \
        -out "$WORK/x.csr"
done

# -newkey: for each algorithm, OpenSSL verifies the request and reads the
# key, the key is the request's, standard error is OpenSSL's, and the key
# file is readable by its owner only (privkey.pem without -keyout).
mode() { perl -e 'printf "%o", (stat shift)[2] & 0777' "$1"; }
"$OPENSSL" ecparam -name secp384r1 -out "$WORK/p384.pem"
newkeys=("ec -pkeyopt ec_paramgen_curve:P-256"
    "ec -pkeyopt ec_paramgen_curve:secp384r1"
    "ec -pkeyopt ec_paramgen_curve:P-521" "ec:$WORK/p384.pem" "ed25519")
for spec in "${newkeys[@]}"; do
    read -r -a args <<<"$spec"
    label="-newkey $spec"
    for who in OPENSSL BALDSSL; do
        mkdir -p "$WORK/$who"
        (cd "$WORK/$who" && "${!who}" req -newkey "${args[@]}" -noenc \
            -subj /CN=new.example -out r.csr 2>err.txt)
    done
    b="$WORK/BALDSSL"
    check "$label: OpenSSL verifies the request" \
        "$OPENSSL" req -in "$b/r.csr" -verify -noout
    "$OPENSSL" pkey -in "$b/privkey.pem" -pubout >"$WORK/k.pub"
    "$OPENSSL" req -in "$b/r.csr" -noout -pubkey >"$WORK/r.pub"
    same "$label: the key is the request's" "$WORK/k.pub" "$WORK/r.pub"
    same "$label: standard error" "$WORK/OPENSSL/err.txt" "$b/err.txt"
    if [[ "$(mode "$b/privkey.pem")" == 600 ]]; then
        interop_pass "$label: key file mode"
    else
        echo "FAIL $label: key file mode $(mode "$b/privkey.pem")"
        fail=$((fail + 1))
    fi
    rm -rf "$WORK/OPENSSL" "$WORK/BALDSSL"
done
"$BALDSSL" req -x509 -newkey ed25519 -noenc -keyout "$WORK/ca-key.pem" \
    -subj /CN=ca.example -out "$WORK/ca.pem" 2>/dev/null
check "-x509 -newkey: OpenSSL verifies the certificate" \
    "$OPENSSL" verify -CAfile "$WORK/ca.pem" "$WORK/ca.pem"
"$OPENSSL" pkey -in "$WORK/ca-key.pem" -pubout >"$WORK/k.pub"
"$OPENSSL" x509 -in "$WORK/ca.pem" -noout -pubkey >"$WORK/c.pub"
same "-x509 -newkey: the key is the certificate's" "$WORK/k.pub" \
    "$WORK/c.pub"
for who in OPENSSL BALDSSL; do
    refuse "$who refuses an EC key without a curve" \
        "${!who}" req -newkey ec -noenc -keyout "$WORK/x.pem" \
        -subj /CN=x -out "$WORK/x.csr"
done

# -verify: the same lines on the same streams (standard error in 3.0,
# standard output for the success from 3.2).
"$OPENSSL" genpkey -algorithm ed25519 -out "$WORK/ed.pem"
"$OPENSSL" req -new -key "$WORK/ed.pem" -subj /CN=v.example \
    -out "$WORK/v.csr"
for who in OPENSSL BALDSSL; do
    "${!who}" req -in "$WORK/v.csr" -verify -noout \
        >"$WORK/$who.out" 2>"$WORK/$who.err"
done
same "-verify: standard output" "$WORK/OPENSSL.out" "$WORK/BALDSSL.out"
same "-verify: standard error" "$WORK/OPENSSL.err" "$WORK/BALDSSL.err"

# -subj=<value>: the value is bytes, as with -subj <value>, so a Latin-1
# subject (not UTF-8) gives OpenSSL's request (Ed25519 is deterministic).
latin1=$'/CN=\xe9t\xe9'
for who in OPENSSL BALDSSL; do
    "${!who}" req -new -key "$WORK/ed.pem" -subj="$latin1" -outform DER \
        -out "$WORK/$who.der"
done
same "-subj=<Latin-1>" "$WORK/OPENSSL.der" "$WORK/BALDSSL.der"

interop_summary req-interop "$pass" "$fail"
