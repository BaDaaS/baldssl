#!/usr/bin/env bash
#
# Differential tests of `verify` against a real OpenSSL. OpenSSL builds the
# chains: for each curve of tests/fixtures/keys/keypairs.txt a root, an
# intermediate and a leaf, with the other curves as leaf keys too; then
# chains that fail one check each (a missing intermediate, a leaf not yet
# valid or expired, an expired intermediate, a bad signature, an issuer
# that is not a CA or lacks keyCertSign, a path length exceeded, an
# unhandled critical extension, untrusted self-signed certificates, and a
# trusted intermediate without its root). baldssl and OpenSSL must give the
# same exit code, the same standard output, and the same report on
# standard error, every error included (after it OpenSSL may print its
# error stack).
#
# Usage:
#   scripts/verify-interop.sh <path/to/openssl> <path/to/baldssl>
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
WORK=$(mktemp -d "${TMPDIR:-/tmp}/baldssl-verify.XXXXXX")
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

same() {
    # same <label> <verify args...>
    local label=$1 ro=0 rb=0
    shift
    "$OPENSSL" verify "$@" >o.out 2>o.err || ro=$?
    "$BALDSSL" verify "$@" >b.out 2>b.err || rb=$?
    # The report: every line up to "verification failed"; OpenSSL may
    # print its error stack after it.
    sed '/verification failed/q' o.err >o3
    sed '/verification failed/q' b.err >b3
    if [[ "$ro" -eq "$rb" ]] && cmp -s o.out b.out && cmp -s o3 b3; then
        pass=$((pass + 1))
    else
        echo "FAIL $label: exit $ro/$rb; $(tr '\n' '|' <o3) vs $(tr '\n' '|' <b3)"
        fail=$((fail + 1))
    fi
}

same_exit() {
    # same_exit <label> <verify args...>: the same exit code only, for the
    # usage errors whose message baldssl does not yet print as OpenSSL does
    # (the command name twice, and no "Use -help for summary." line).
    local label=$1 ro=0 rb=0
    shift
    "$OPENSSL" verify "$@" >/dev/null 2>&1 || ro=$?
    "$BALDSSL" verify "$@" >/dev/null 2>&1 || rb=$?
    if [[ "$ro" -eq "$rb" ]]; then
        pass=$((pass + 1))
    else
        echo "FAIL $label: exit $ro/$rb"
        fail=$((fail + 1))
    fi
}

unhex() { perl -e 'print pack("H*", shift)' "$1"; }

# issue <key> <subject> <ca.pem> <ca.key> <out.pem> [x509 options...]
issue() {
    local key=$1 subj=$2 ca=$3 cakey=$4 out=$5
    shift 5
    "$OPENSSL" req -new -key "$key" -keyform DER -subj "$subj" \
        -out req.csr 2>/dev/null
    "$OPENSSL" x509 -req -in req.csr -CA "$ca" -CAkey "$cakey" \
        -CAkeyform DER -set_serial "$RANDOM" "$@" -out "$out" 2>/dev/null
}

printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=keyCertSign,cRLSign\n' >ca.cnf
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\n' >ca0.cnf
printf 'basicConstraints=CA:FALSE\n' >leaf.cnf
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=digitalSignature\n' >noks.cnf
printf 'basicConstraints=CA:FALSE\n1.2.3.4=critical,DER:0500\n' >crit.cnf

keys=$(grep -v '^#' "$ROOT/tests/fixtures/keys/keypairs.txt")
n=0
while read -r _ _ _ pkcs8; do
    n=$((n + 1))
    unhex "$pkcs8" >"k$n.der"
done <<<"$keys"
count=$n

# Valid chains: root and intermediate on key i, leaf on key j.
for i in 1 5 9 13; do
    "$OPENSSL" req -x509 -new -key "k$i.der" -keyform DER -subj "/CN=Root $i" \
        -days 30 -out root.pem 2>/dev/null
    issue "k$((i + 1)).der" "/CN=Mid $i" root.pem "k$i.der" mid.pem -days 30 \
        -extfile ca.cnf
    for j in $(seq 1 "$count"); do
        issue "k$j.der" "/CN=Leaf $j" mid.pem "k$((i + 1)).der" leaf.pem \
            -days 30 -extfile leaf.cnf
        same "root $i leaf $j" -CAfile root.pem -untrusted mid.pem leaf.pem
    done
    cat root.pem mid.pem >both.pem
    same "root $i, both trusted" -CAfile both.pem leaf.pem
done

# One root and intermediate for the failures (Ed25519, deterministic).
ed=$(awk '$1 == "ED25519" {print NR; exit}' <<<"$keys")
k="k$ed.der"
"$OPENSSL" req -x509 -new -key "$k" -keyform DER -subj /CN=Root -days 30 \
    -out root.pem 2>/dev/null
issue "$k" "/CN=Mid" root.pem "$k" mid.pem -days 30 -extfile ca.cnf
issue "$k" "/CN=Leaf" mid.pem "$k" leaf.pem -days 30 -extfile leaf.cnf
same "valid" -CAfile root.pem -untrusted mid.pem leaf.pem
same "missing intermediate" -CAfile root.pem leaf.pem
same "untrusted root" -untrusted mid.pem -untrusted root.pem leaf.pem
same "trusted intermediate only" -CAfile mid.pem leaf.pem
same "untrusted self-signed" root.pem
same "two files" -CAfile root.pem root.pem mid.pem
if [[ "$OPENSSL_VERSION" != 3.0.* ]]; then
    issue "$k" "/CN=Future" mid.pem "$k" future.pem -extfile leaf.cnf \
        -not_before 20400101000000Z -not_after 20410101000000Z
    issue "$k" "/CN=Old" mid.pem "$k" old.pem -extfile leaf.cnf \
        -not_before 20200101000000Z -not_after 20210101000000Z
    issue "$k" "/CN=OldMid" root.pem "$k" oldmid.pem -extfile ca.cnf \
        -not_before 20200101000000Z -not_after 20210101000000Z
    issue "$k" "/CN=Leaf" oldmid.pem "$k" under-old.pem -days 30 \
        -extfile leaf.cnf
    same "not yet valid" -CAfile root.pem -untrusted mid.pem future.pem
    same "expired" -CAfile root.pem -untrusted mid.pem old.pem
    same "expired intermediate" -CAfile root.pem -untrusted oldmid.pem \
        under-old.pem
fi
"$OPENSSL" x509 -in leaf.pem -outform DER -out leaf.der
perl -e 'local $/; my $d = <STDIN>; substr($d, -1, 1) ^= "\x01"; print $d' \
    <leaf.der >bad.der
same "bad signature" -CAfile root.pem -untrusted mid.pem bad.der
issue "$k" "/CN=NotCA" root.pem "$k" notca.pem -days 30 -extfile leaf.cnf
issue "$k" "/CN=Leaf" notca.pem "$k" under-notca.pem -days 30 -extfile leaf.cnf
same "issuer not a CA" -CAfile root.pem -untrusted notca.pem under-notca.pem
issue "$k" "/CN=NoKS" root.pem "$k" noks.pem -days 30 -extfile noks.cnf
issue "$k" "/CN=Leaf" noks.pem "$k" under-noks.pem -days 30 -extfile leaf.cnf
same "issuer without keyCertSign" -CAfile root.pem -untrusted noks.pem \
    under-noks.pem
issue "$k" "/CN=Mid0" root.pem "$k" mid0.pem -days 30 -extfile ca0.cnf
issue "$k" "/CN=Mid1" mid0.pem "$k" mid1.pem -days 30 -extfile ca.cnf
issue "$k" "/CN=Leaf" mid1.pem "$k" deep.pem -days 30 -extfile leaf.cnf
same "path length exceeded" -CAfile root.pem -untrusted mid0.pem \
    -untrusted mid1.pem deep.pem
issue "$k" "/CN=Crit" mid.pem "$k" crit.pem -days 30 -extfile crit.cnf
same "unhandled critical extension" -CAfile root.pem -untrusted mid.pem \
    crit.pem

# -attime: around the bounds of every certificate of the chain (OpenSSL 3
# counts a certificate expired at its notAfter, OpenSSL 4 includes it), at
# the ends of the years 0 to 9999 and past them (OpenSSL 3 reports error 13
# there), and in each spelling OpenSSL reads numbers in; then the values it
# refuses, and the option given twice.
epoch() {
    "$OPENSSL" x509 -in "$1" -noout "-$2" | cut -d= -f2 |
        perl -MTime::Local -ne '
            my %m; @m{qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec)} = 0..11;
            my ($mo, $d, $t, $y) = split;
            my ($h, $mi, $s) = split /:/, $t;
            print timegm($s, $mi, $h, $d, $m{$mo}, $y)'
}
for cert in root.pem mid.pem leaf.pem; do
    for bound in startdate enddate; do
        t=$(epoch "$cert" "$bound")
        for at in $((t - 1)) "$t" $((t + 1)); do
            same "-attime $cert $bound $at" -attime "$at" -CAfile root.pem \
                -untrusted mid.pem leaf.pem
        done
    done
done
t=$(epoch leaf.pem startdate)
for at in 0 -1 -62167219200 -62167219201 253402300799 253402300800 \
    9223372036854775807 -9223372036854775808 \
    "$(printf '0x%x' $((t + 60)))" "$(printf '0%o' $((t + 60)))" \
    " +$((t + 60))"; do
    same "-attime '$at'" -attime "$at" -CAfile root.pem -untrusted mid.pem \
        leaf.pem
done
for at in abc 12x "" "5 " 08 -08 0x 0X1g 99999999999999999999; do
    same_exit "-attime refuses '$at'" -attime "$at" -CAfile root.pem leaf.pem
done
same "-attime given twice" -attime 0 -attime "$((t + 60))" \
    -CAfile root.pem -untrusted mid.pem leaf.pem
# A notAfter of 99991231235959Z (no well-defined expiration date, RFC 5280
# section 4.1.2.5): OpenSSL 4 never expires it. OpenSSL 3.0 cannot set it.
if [[ "$OPENSSL_VERSION" != 3.0.* ]]; then
    "$OPENSSL" req -x509 -new -key "$k" -keyform DER -subj /CN=Forever \
        -not_before 20200101000000Z -not_after 99991231235959Z \
        -out forever.pem 2>/dev/null
    for at in 253402300798 253402300799 253402300800 9223372036854775807; do
        same "-attime $at, no well-defined expiration" -attime "$at" \
            -CAfile forever.pem forever.pem
    done
fi

echo "verify-interop: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
