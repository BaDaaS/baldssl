<p align="center">
  <img src="website/res/baldssl-lockup-light.svg" alt="baldssl" width="420">
</p>

<p align="center">
  <a href="https://badaas.be/baldssl/">badaas.be/baldssl</a>
</p>

Developer documentation for baldssl, a reimplementation of the `openssl`
command-line tool in Rust with no third-party dependencies.

To install and use baldssl, see the website:
[badaas.be/baldssl](https://badaas.be/baldssl/) (installation, command status,
compatibility with OpenSSL versions, differences from OpenSSL).

## building

```sh
make build        # debug build
make ci           # everything CI checks that needs no OpenSSL
make help         # all targets
```

The toolchain is pinned in `rust-toolchain.toml` (latest stable). Formatting
uses nightly `rustfmt` and `taplo`; `make setup` installs the tools.

## OpenSSL compatibility profiles

OpenSSL 3.x and 4.x print `-text` differently (hex dump geometry, the RSA
modulus sign byte, the EC key header), so the printer takes a profile:
`baldssl_x509::text::Compat` (`V3`, `V4`), chosen by the CLI from
`BALDSSL_OPENSSL_COMPAT`. Golden files exist per profile
(`tests/fixtures/golden/v3`, `v4`, recorded from OpenSSL 3.5.9 and 4.1.0), and
`scripts/interop.sh` picks the profile from the version of the OpenSSL under
test. CI requires 3.5.9 and 4.1.0 to pass; 3.0.22, 3.6.5 and 4.0.3 run as
informational jobs.

Rule for new output: never print something OpenSSL would print differently.
Unimplemented cases return `Error::Unsupported` and get a `TODO.md` entry.

## testing

| Layer                   | What                                                                                                             | Where                                           |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| Unit and property tests | laws of each primitive (base64 and DER canonicity, hash streaming, UTF-8 encoding, option order) with `proptest` | `cargo test`                                    |
| Known answers           | FIPS 180-4 vectors for SHA-1/224/256/384/512, RFC 4648 vectors                                                   | `cargo test`                                    |
| Golden files            | byte-for-byte output of OpenSSL 3.5.9 and 4.1.0 on 12 certificates x 20 argument sets                            | `crates/baldssl/tests/golden.rs`, `make golden` |
| Interop                 | live diff against an OpenSSL binary; baldssl re-encodings must be read back and verified by OpenSSL              | `make interop OPENSSL=...`                      |
| Robustness              | corrupted certificates never panic; truncations are rejected                                                     | `crates/baldssl-x509/tests/robustness.rs`       |
| Fuzzing                 | `base64`, `pem`, `der`, `x509` targets (nightly, daily in CI)                                                    | `make fuzz FUZZ_TARGET=x509`                    |
| Mutation testing        | surviving mutants are missing tests (weekly in CI)                                                               | `make mutants`                                  |
| Coverage                | tarpaulin, uploaded as a CI artifact                                                                             | `make coverage`                                 |

## platforms

CI runs the test suite natively on Linux, macOS and Windows, each on x86_64 and
aarch64, with Rust stable, beta and nightly. Cross jobs run it under QEMU for
ARMv7 and ARMv6 (Raspberry Pi with a 32-bit OS), riscv64, and natively for
32-bit x86 on Linux and Windows.

### WebAssembly

The libraries build for `wasm32-unknown-unknown` (the browser target), and the
whole CLI builds for `wasm32-wasip1`. CI runs the library tests as WebAssembly
and runs the golden-file suite against the WebAssembly CLI through `wasmtime`,
so the WebAssembly build is checked against OpenSSL's output like the native
one:

```sh
make build-wasm   # target/wasm32-wasip1/release/baldssl.wasm
make test-wasm    # needs wasmtime
scripts/wasmtime-baldssl.sh x509 -in cert.crt -noout -text
```

## website

The website (`website/`, plain HTML and Tailwind CSS, built with Vite) is the
user documentation, deployed to GitHub Pages by `.github/workflows/pages.yml` on
every push to `main` that touches `website/`. Its command table is generated
from `website/src/commands.json`; update a command's `status` and `note` there
when implementing it:

```sh
make website-install website-build   # website/dist
make website-commands OPENSSL_3=... OPENSSL_4=...   # refresh the table
```

A test (`crates/baldssl/tests/commands.rs`) fails if the table marks a command
as implemented that the binary does not dispatch, or the reverse.

## layout

| Crate            | Contents                                                      |
| ---------------- | ------------------------------------------------------------- |
| `baldssl`        | the CLI; OpenSSL-style option parsing; one module per command |
| `baldssl-core`   | error type, base64, PEM, strict DER reader, hex               |
| `baldssl-crypto` | SHA-1, SHA-2 (more primitives planned)                        |
| `baldssl-x509`   | certificate decoding and OpenSSL-exact printing               |

`proofs/` is the Lean 4 project (compile-only skeleton for now, built in CI
against the pinned Aeneas library). `fuzz/` holds the cargo-fuzz targets.

## dependencies

None at run or build time: `make check-no-deps` (run in CI) fails if any
third-party crate reaches a normal or build dependency edge. `proptest` is used
for tests only, and `libfuzzer-sys` only inside `fuzz/`.

## license

MIT
