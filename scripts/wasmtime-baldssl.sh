#!/usr/bin/env bash
#
# Runs the WebAssembly (WASI) build of baldssl with wasmtime, with the same
# command line as the native binary, so the native test suites can run
# against it (BALDSSL_BIN=scripts/wasmtime-baldssl.sh cargo test ...).
#
# Usage:
#   scripts/wasmtime-baldssl.sh x509 -in cert.crt -noout -text
#

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WASM=${BALDSSL_WASM:-$ROOT/target/wasm32-wasip1/release/baldssl.wasm}

# The whole host filesystem is visible at the same paths, as for a native
# process.
exec wasmtime run --dir / "$WASM" "$@"
