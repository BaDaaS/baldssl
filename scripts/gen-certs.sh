#!/usr/bin/env bash
#
# Generates the self-signed test certificates with a given OpenSSL: P-256,
# P-384, P-521, Ed25519 and RSA keys; small, large and negative serials;
# multi-valued RDNs, UTF-8 names; every extension baldssl prints, and one
# extension OpenSSL does not know. Keys are deleted.
#
# Usage:
#   scripts/gen-certs.sh <path/to/openssl> <output-dir>
#

set -euo pipefail

if [[ "$#" -ne 2 ]]; then
    echo "usage: $0 <openssl> <output-dir>" >&2
    exit 2
fi
OPENSSL=$1
OUT=$2
mkdir -p "$OUT"
KEYS=$(mktemp -d "${TMPDIR:-/tmp}/baldssl-keys.XXXXXX")
trap 'rm -rf "$KEYS"' EXIT

# A minimal config so `req` never depends on the system openssl.cnf.
CONF="$KEYS/req.cnf"
printf '[req]\ndistinguished_name = dn\n[dn]\n' >"$CONF"

status=0

gen() {
    # gen <name> <key-args...> -- <req-args...>
    local name=$1
    shift
    local keyargs=()
    while [[ "$1" != "--" ]]; do
        keyargs+=("$1")
        shift
    done
    shift
    if ! "$OPENSSL" req -x509 -config "$CONF" "${keyargs[@]}" -nodes \
        -keyout "$KEYS/$name.key" -out "$OUT/$name.crt" -days 3650 "$@" \
        2>"$KEYS/$name.err"; then
        echo "error generating $name:" >&2
        cat "$KEYS/$name.err" >&2
        status=1
    fi
}

P256=(-newkey ec -pkeyopt ec_paramgen_curve:P-256)
SAN="DNS:a.example,DNS:b.example,IP:10.0.0.1,IP:2001:db8::1"
SAN="$SAN,email:x@example.com,URI:https://example.com/,RID:1.2.3.4"
KU="critical,digitalSignature,nonRepudiation,keyEncipherment"
KU="$KU,dataEncipherment,keyAgreement,keyCertSign,cRLSign,encipherOnly"
KU="$KU,decipherOnly"
EKU="serverAuth,clientAuth,codeSigning,emailProtection,timeStamping"
EKU="$EKU,OCSPSigning,1.2.3.4.5"

gen p256-full "${P256[@]}" -- -subj "/C=BE/O=BaDaaS/CN=full.example" \
    -addext "subjectAltName=$SAN" -addext "keyUsage=$KU" \
    -addext "extendedKeyUsage=$EKU" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:2"
gen p256-serial "${P256[@]}" -- -subj "/CN=serial" -set_serial 4660
gen p256-negserial "${P256[@]}" -- -subj "/CN=neg" \
    -set_serial -0x0102030405060708090a
gen p256-bigserial "${P256[@]}" -- -subj "/CN=big" \
    -set_serial 0x7fffffffffffffffff
gen p256-mvrdn "${P256[@]}" -- -multivalue-rdn \
    -subj "/CN=a+OU=b/O=Comma, Inc./DC=example/DC=com"
gen p256-utf8 "${P256[@]}" -- -utf8 \
    -subj "/CN=H$(printf '\303\251')l$(printf '\303\250')ne/O=Caf$(printf '\303\251')"
gen p256-unknown-ext "${P256[@]}" -- -subj "/CN=unknown-ext" \
    -addext "1.2.3.4.5.6=ASN1:UTF8String:hello" \
    -addext "basicConstraints=CA:FALSE"
gen p384 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -- -subj "/CN=p384" \
    -addext "subjectAltName=DNS:p384.example" -sha384
gen p521 -newkey ec -pkeyopt ec_paramgen_curve:P-521 -- -subj "/CN=p521" \
    -sha512
gen ed25519 -newkey ed25519 -- -subj "/CN=ed25519"
gen rsa2048 -newkey rsa:2048 -- -subj "/CN=rsa2048" \
    -addext "extendedKeyUsage=serverAuth"
gen rsa3072 -newkey rsa:3072 -- -subj "/CN=rsa3072" -sha384

exit "$status"
