#!/usr/bin/env bash
# Builds and runs the os_rng tests inside a container of another Linux
# distribution, linked against that distribution's glibc by its own C
# toolchain, to check the glibc versions os_rng claims to support.
#
# Usage: test-os-rng-glibc.sh <image> <expect>
#   image   a Docker image with a C toolchain, e.g. buildpack-deps:bionic
#   expect  "pass": the tests build, run and pass, and the binary imports
#                   getrandom at symbol version GLIBC_2.25;
#           "link-fail": linking fails on an undefined getrandom (an image
#                   below glibc 2.25, the documented minimum).
#
# No Rust is installed in the container: the host's toolchain (the one
# rust-toolchain.toml pins) is mounted read-only. Rust's linux-gnu
# toolchains are built against an old glibc, so they run on old distributions,
# and the crates are fetched on the host first, so the container needs no
# network access to crates.io.
set -euo pipefail

image="${1:?usage: test-os-rng-glibc.sh <image> <pass|link-fail>}"
expect="${2:?usage: test-os-rng-glibc.sh <image> <pass|link-fail>}"
case "$expect" in
pass | link-fail) ;;
*)
    echo "expect must be pass or link-fail, not $expect" >&2
    exit 2
    ;;
esac

root="$(cd "$(dirname "$0")/.." && pwd)"
sysroot="$(rustc --print sysroot)"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
tag="$(echo "$image" | tr ':/' '--')"

(cd "$root" && cargo fetch --locked)

# Runs as the invoking user, so files written into the checkout are not
# owned by root; HOME is a scratch directory the user can write.
log="$(mktemp)"
set +e
docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp \
    -e CARGO_HOME=/cargo \
    -e CARGO_TARGET_DIR="/src/target/glibc-$tag" \
    -e CARGO_TERM_COLOR=never \
    -v "$sysroot:/rust:ro" \
    -v "$cargo_home:/cargo" \
    -v "$root:/src" \
    -w /src \
    "$image" \
    sh -c '
        set -e
        export PATH=/rust/bin:$PATH
        echo "glibc: $(ldd --version | head -n 1)"
        # Plain sh has no pipefail: log to a file, then test cargo itself.
        if ! cargo test --frozen -p baldssl-crypto --lib --no-run \
            >/tmp/build.log 2>&1; then
            cat /tmp/build.log
            exit 1
        fi
        cat /tmp/build.log
        bin=$(sed -n "s/.*Executable unittests src\/lib.rs (\(.*\))/\1/p" \
            /tmp/build.log | head -n 1)
        echo "getrandom import:"
        objdump -T "$bin" | grep -w getrandom
        objdump -T "$bin" | grep -w getrandom | grep -q "GLIBC_2\.25"
        "$bin" os_rng
    ' >"$log" 2>&1
status=$?
set -e
cat "$log"

if [[ "$expect" == pass ]]; then
    if [[ "$status" -ne 0 ]]; then
        echo "FAIL $image: expected the os_rng tests to pass" >&2
        exit 1
    fi
    echo "ok $image: os_rng builds, imports getrandom@GLIBC_2.25 and passes"
else
    if [[ "$status" -eq 0 ]]; then
        echo "FAIL $image: expected linking to fail below glibc 2.25" >&2
        exit 1
    fi
    if ! grep -Eq "undefined (reference to|symbol:) .?getrandom" "$log"; then
        echo "FAIL $image: failed, but not on an undefined getrandom" >&2
        exit 1
    fi
    echo "ok $image: linking fails on getrandom, below the minimum glibc"
fi
