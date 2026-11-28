#!/usr/bin/env bash
#
# Differential tests of `x509 -req` against a real OpenSSL, for one CA per
# curve (the first fixture key of each) and every key of
# tests/fixtures/keys/keypairs.txt as the subject of a request:
#
# - OpenSSL verifies the certificate baldssl issues (`openssl verify
#   -CAfile`), and both print the same on standard error;
# - with a fixed serial and validity, Ed25519-signed certificates are
#   identical to OpenSSL's and ECDSA-signed ones print the same fields
#   (OpenSSL 3.0's x509 has no -not_before, so there the dates are left
#   out of the comparison);
# - -CAcreateserial and -CAserial leave the serial file as OpenSSL does;
# - a changed request, and a CA key that is not the CA's, are refused by
#   both;
# - extension files (-extfile, -extensions, @sections, repeated names) and
#   -copy_extensions give the same certificates and the same errors.
#
# Usage:
#   scripts/x509-req-interop.sh <path/to/openssl> <path/to/baldssl>
#
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
    echo "usage: $0 <openssl> <baldssl>" >&2
    exit 2
fi
OPENSSL=$1
BALDSSL=$2
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/baldssl-x509-req.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=scripts/interop-profile.sh
source "$ROOT/scripts/interop-profile.sh"
pass=0
fail=0

ok() { pass=$((pass + 1)); }
ko() {
    echo "FAIL $1"
    fail=$((fail + 1))
}
same() { if cmp -s "$2" "$3"; then ok; else ko "$1: outputs differ"; fi; }
refuse() {
    # refuse <label> <command...>: the command must fail.
    local label=$1
    shift
    if "$@" >/dev/null 2>&1; then ko "$label: accepted"; else ok; fi
}
unhex() { perl -e 'print pack("H*", shift)' "$1"; }

if [[ "$OPENSSL_VERSION" == 3.0.* ]]; then
    validity=(-days 30)
    fields=(-noout -subject -issuer -serial -pubkey -ext
        "subjectKeyIdentifier,authorityKeyIdentifier")
else
    validity=(-not_before 20261122000000Z -not_after 20510101000000Z)
    fields=(-noout -subject -issuer -serial -dates -pubkey -ext
        "subjectKeyIdentifier,authorityKeyIdentifier")
fi

keys=$(grep -v '^#' "$ROOT/tests/fixtures/keys/keypairs.txt")
seen=""
while read -r ca_curve _ _ ca_pkcs8; do
    [[ " $seen " == *" $ca_curve "* ]] && continue
    seen="$seen $ca_curve"
    unhex "$ca_pkcs8" >"$WORK/ca.der"
    "$OPENSSL" req -x509 -new -key "$WORK/ca.der" -keyform DER \
        -subj "/CN=Example CA" -days 3650 -out "$WORK/ca.crt" 2>/dev/null
    n=0
    while read -r curve _ _ pkcs8; do
        n=$((n + 1))
        label="CA $ca_curve, $curve $n"
        unhex "$pkcs8" >"$WORK/leaf.der"
        "$OPENSSL" req -new -key "$WORK/leaf.der" -keyform DER \
            -subj "/CN=leaf.example/O=Org" -out "$WORK/r.csr" 2>/dev/null
        args=(-req -in "$WORK/r.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.der"
            -CAkeyform DER -set_serial 0x0102 "${validity[@]}")
        "$OPENSSL" x509 "${args[@]}" -out "$WORK/o.pem" 2>"$WORK/o.err"
        if ! "$BALDSSL" x509 "${args[@]}" -out "$WORK/b.pem" \
            2>"$WORK/b.err"; then
            ko "$label: baldssl failed: $(head -3 "$WORK/b.err")"
            continue
        fi
        if "$OPENSSL" verify -CAfile "$WORK/ca.crt" "$WORK/b.pem" \
            >/dev/null 2>&1; then
            ok
        else
            ko "$label: OpenSSL does not verify baldssl's certificate"
        fi
        same "$label: standard error" "$WORK/o.err" "$WORK/b.err"
        if [[ "$ca_curve" == "ED25519" && "$OPENSSL_VERSION" != 3.0.* ]]; then
            same "$label: identical" "$WORK/o.pem" "$WORK/b.pem"
        else
            "$OPENSSL" x509 -in "$WORK/o.pem" "${fields[@]}" >"$WORK/o.txt"
            "$OPENSSL" x509 -in "$WORK/b.pem" "${fields[@]}" >"$WORK/b.txt"
            same "$label: fields" "$WORK/o.txt" "$WORK/b.txt"
        fi
    done <<<"$keys"

    # Serial files: created, then read, incremented and written back.
    label="CA $ca_curve serial file"
    cp "$WORK/ca.crt" "$WORK/b-ca.crt"
    "$BALDSSL" x509 -req -in "$WORK/r.csr" -CA "$WORK/b-ca.crt" \
        -CAkey "$WORK/ca.der" -CAkeyform DER -CAcreateserial \
        -out "$WORK/b.pem" 2>/dev/null
    if [[ -f "$WORK/b-ca.srl" ]] &&
        [[ "serial=$(cat "$WORK/b-ca.srl")" == \
        "$("$OPENSSL" x509 -in "$WORK/b.pem" -noout -serial)" ]]; then
        ok
    else
        ko "$label: -CAcreateserial"
    fi
    for start in 0A FF 7F; do
        echo "$start" >"$WORK/o.srl"
        echo "$start" >"$WORK/b.srl"
        "$OPENSSL" x509 -req -in "$WORK/r.csr" -CA "$WORK/ca.crt" \
            -CAkey "$WORK/ca.der" -CAkeyform DER -CAserial "$WORK/o.srl" \
            -out "$WORK/o.pem" 2>/dev/null
        "$BALDSSL" x509 -req -in "$WORK/r.csr" -CA "$WORK/ca.crt" \
            -CAkey "$WORK/ca.der" -CAkeyform DER -CAserial "$WORK/b.srl" \
            -out "$WORK/b.pem" 2>/dev/null
        same "$label: -CAserial from $start" "$WORK/o.srl" "$WORK/b.srl"
    done

    # Refusals: a changed request, and the wrong CA key.
    "$OPENSSL" req -in "$WORK/r.csr" -outform DER -out "$WORK/r.der"
    perl -e 'local $/; my $d = <STDIN>; substr($d, -1, 1) ^= "\x01";
        print $d' <"$WORK/r.der" >"$WORK/bad.der"
    for who in OPENSSL BALDSSL; do
        if "${!who}" x509 -req -in "$WORK/bad.der" -inform DER \
            -CA "$WORK/ca.crt" -CAkey "$WORK/ca.der" -CAkeyform DER \
            -set_serial 1 -out "$WORK/x.pem" >/dev/null 2>&1; then
            ko "CA $ca_curve: $who accepts a changed request"
        else
            ok
        fi
        if "${!who}" x509 -req -in "$WORK/r.csr" -CA "$WORK/ca.crt" \
            -CAkey "$WORK/leaf.der" -CAkeyform DER -set_serial 1 \
            -out "$WORK/x.pem" >/dev/null 2>&1; then
            ko "CA $ca_curve: $who accepts another CA key"
        else
            ok
        fi
    done
done <<<"$keys"

# Extension files and copied extensions: one Ed25519 CA, one request with
# extensions, and a set of configuration files. The certificates are
# identical (OpenSSL 3.0's x509 has no -not_before, so there only the
# extensions are compared), and standard error is the same.
ed_key=$(grep '^ED25519' "$ROOT/tests/fixtures/keys/keypairs.txt" | head -1 |
    awk '{print $4}')
unhex "$ed_key" >"$WORK/edca.der"
"$OPENSSL" req -x509 -new -key "$WORK/edca.der" -keyform DER \
    -subj "/CN=Example CA" -days 3650 -out "$WORK/edca.crt" 2>/dev/null
"$OPENSSL" req -new -key "$WORK/leaf.der" -keyform DER -subj /CN=leaf \
    -addext "subjectAltName=DNS:leaf.example" \
    -addext "keyUsage=digitalSignature" -out "$WORK/ext.csr" 2>/dev/null
cat >"$WORK/a.cnf" <<'CNF'
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature # a comment
[ server ]
subjectAltName = @alt
extendedKeyUsage = serverAuth
[alt]
DNS.1 = s.example
IP.1 = 10.0.0.1
CNF
printf 'extensions = named\nkeyUsage = cRLSign\n[ named ]\nbasicConstraints = CA:TRUE,pathlen:0\n' \
    >"$WORK/b.cnf"
printf 'subjectAltName = DNS:one.example\nkeyUsage = digitalSignature\nsubjectAltName = DNS:two.example\n' \
    >"$WORK/c.cnf"
cases=("-extfile $WORK/a.cnf" "-extfile $WORK/a.cnf -extensions server"
    "-extfile $WORK/b.cnf" "-extfile $WORK/c.cnf" "-copy_extensions copy"
    "-copy_extensions copy -extfile $WORK/a.cnf -extensions server"
    "-copy_extensions copyall -extfile $WORK/a.cnf")
for args in "${cases[@]}"; do
    read -r -a extra <<<"$args"
    label="extensions ${args//$WORK\//}"
    common=(-req -in "$WORK/ext.csr" -CA "$WORK/edca.crt" -CAkey "$WORK/edca.der"
        -CAkeyform DER -set_serial 9 "${validity[@]}" "${extra[@]}")
    "$OPENSSL" x509 "${common[@]}" -out "$WORK/o.pem" 2>"$WORK/o.err"
    "$BALDSSL" x509 "${common[@]}" -out "$WORK/b.pem" 2>"$WORK/b.err"
    same "$label: standard error" "$WORK/o.err" "$WORK/b.err"
    if [[ "$OPENSSL_VERSION" == 3.0.* ]]; then
        for who in o b; do
            "$OPENSSL" x509 -in "$WORK/$who.pem" -noout -text |
                sed -n '/X509v3 extensions/,/Signature Algorithm/p' \
                    >"$WORK/$who.txt"
        done
        same "$label: extensions" "$WORK/o.txt" "$WORK/b.txt"
    else
        same "$label: identical" "$WORK/o.pem" "$WORK/b.pem"
    fi
done
for who in OPENSSL BALDSSL; do
    refuse "$who refuses a missing section" "${!who}" x509 -req \
        -in "$WORK/ext.csr" -CA "$WORK/edca.crt" -CAkey "$WORK/edca.der" \
        -CAkeyform DER -extfile "$WORK/a.cnf" -extensions nope \
        -out "$WORK/x.pem"
done

interop_summary x509-req-interop "$pass" "$fail"
