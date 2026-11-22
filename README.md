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

OpenSSL releases print `-text` differently, so the printer takes a profile,
`baldssl_x509::text::Compat`, chosen by the CLI from `BALDSSL_OPENSSL_COMPAT`:

| Profile | Release line | Differences                                                                        |
| ------- | ------------ | ---------------------------------------------------------------------------------- |
| `3.0`   | OpenSSL 3.0  | names in the older escaped style (`CN = x`, `\XX` escapes, quoted values)          |
| `3`     | OpenSSL 3.5  | the default                                                                        |
| `4`     | OpenSSL 4.x  | hex dump geometry, no RSA modulus sign byte, EC key header with the security level |

Golden files exist per profile (`golden/v30`, `v3`, `v4` in the fixtures,
recorded from OpenSSL 3.0.22, 3.5.9 and 4.1.0), and `scripts/interop.sh` picks
the profile from the version of the OpenSSL under test. CI requires 3.0.22,
3.5.9, 3.6.5, 4.0.3 and 4.1.0 to pass. One exception is documented in the
script: OpenSSL 3.0's `x509` silently ignores unknown options, which baldssl
rejects.

Rule for new output: never print something OpenSSL would print differently.
Unimplemented cases return `Error::Unsupported`; the status of each command is
kept in `website/src/commands.json` (see the website section).

## testing

The test fixtures (certificates, keys, and OpenSSL's golden outputs) live in
[baldssl-fixtures](https://github.com/BaDaaS/baldssl-fixtures). `make fixtures`
downloads the release archive pinned in `tests/fixtures.mk` (a tag and its
SHA-256), checks the hash and unpacks it into `tests/fixtures`; `make test` and
the other targets that read fixtures do it first. A new set of fixtures is a new
release there and a new pin here.

| Layer                   | What                                                                                                             | Where                                                 |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| Unit and property tests | laws of each primitive (base64 and DER canonicity, hash streaming, UTF-8 encoding, option order) with `proptest` | `cargo test`                                          |
| Known answers           | FIPS 180-4 vectors for SHA-1/224/256/384/512, RFC 4648 vectors                                                   | `cargo test`                                          |
| Golden files            | byte-for-byte output of OpenSSL 3.5.9 and 4.1.0 on 12 certificates x 20 argument sets                            | `crates/baldssl/tests/golden.rs`, `make check-golden` |
| Interop                 | live diff against an OpenSSL binary; baldssl re-encodings must be read back and verified by OpenSSL              | `make interop OPENSSL=...`                            |
| Robustness              | corrupted certificates never panic; truncations are rejected                                                     | `crates/baldssl-x509/tests/robustness.rs`             |
| Fuzzing                 | `base64`, `pem`, `der`, `x509` targets (nightly, daily in CI)                                                    | `make fuzz FUZZ_TARGET=x509`                          |
| Mutation testing        | surviving mutants are missing tests (weekly in CI)                                                               | `make mutants`                                        |
| Coverage                | tarpaulin, uploaded as a CI artifact                                                                             | `make coverage`                                       |

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

The "Building blocks" table lists the primitives baldssl implements, from
`website/src/primitives.json`; the pull request that implements a primitive sets
its status to `implemented` there.

Every command the website shows (the common tasks, the install and usage
snippets) lives in `website/src/examples.json`, and the page renders them
verbatim with a copy button. `make website-examples OPENSSL=...` runs them all
in order, in one directory: each must work with OpenSSL, tasks marked
`supported` must give byte-identical output and files with baldssl in place of
`openssl`, and a deterministic `not-yet` task fails the check once baldssl
reproduces it, so its status gets updated. CI runs it against OpenSSL 3.5.9 and
4.1.0, including the `cargo install` command.

## Engineering practices

The same list is on the website, rendered from `website/src/practices.json`;
`make check-practices` keeps the two in step.

- **No third-party dependencies.** Every primitive (base64, PEM, DER, the
  hashes, the fields and curves, argument parsing) is implemented in the
  repository. proptest is used only by tests, and libfuzzer-sys only by the fuzz
  targets. Checked by: make check-no-deps fails if a third-party crate reaches a
  normal or build dependency.
- **unsafe in one module.** The workspace denies unsafe code. The one exception
  is the operating system's random number interface, in baldssl-crypto's os_rng
  module. Checked by: make check-unsafe fails on unsafe anywhere else.
- **Output identical to OpenSSL.** Commands print what OpenSSL prints, byte for
  byte; an input baldssl cannot print exactly is rejected as unsupported rather
  than printed differently. Checked by: Golden files recorded from OpenSSL
  3.0.22, 3.5.9 and 4.1.0, and a live differential test against OpenSSL 3.0.22,
  3.5.9, 3.6.5, 4.0.3 and 4.1.0, in both directions.
- **Laws as property tests.** Each structure is a trait whose laws are stated in
  its documentation: the field and group axioms, the isomorphisms between curve
  models, the scalar multiplication as a module action, and the round trip and
  canonicity of every encoding. Checked by: Each law is a generic property test
  that every implementation runs.
- **Known answers from the specifications.** Test vectors come from the
  standards and from OpenSSL (FIPS 180-4, RFC 4648, RFC 8032, SEC 2, key pairs
  generated by OpenSSL), not from baldssl's own output. Checked by: cargo test,
  in CI.
- **Strict, canonical decoding.** Decoders accept exactly one encoding of each
  value: DER rather than BER, canonical base64, field elements below the
  modulus, points on the curve. Checked by: Canonicity tests over arbitrary byte
  strings, and fuzzing.
- **Constant time by construction.** Predicates on secret data return a Choice,
  not a bool, and selection replaces branching. Constant-time and variable-time
  group laws are distinct traits, so a variable-time implementation cannot reach
  a secret. This is a design discipline, not yet a verified property. Checked
  by: Code review and the type system.
- **Fuzzing, mutation testing, coverage.** Fuzz targets for base64, PEM, DER and
  X.509; mutation testing reports the mutants no test kills; test coverage is
  measured. Checked by: Fuzzing daily and mutation testing weekly in CI;
  coverage on every run.
- **Strict lints, three toolchains.** Clippy's pedantic set, with unwrap,
  expect, panic, indexing and unchecked arithmetic denied; the toolchain is
  pinned, and the tests run on Rust stable, beta and nightly. Checked by: make
  lint, in CI on each toolchain.
- **Conventions checked, not remembered.** Trait bounds are written in where
  clauses, imports sit at the top of their module and never inside a function or
  block, a function returning an Option carries the `_opt` suffix (one that can
  fail returns a Result with the reason), and the code mentions no issue or pull
  request: it describes itself. Checked by: make check-where-clauses, make
  check-use-at-top and make check-opt-suffix, in CI.
- **Every citation linked.** Every standard, paper and formula cited in the code
  links its source, down to the section. Checked by: make check-urls checks
  every URL in the sources and in the rendered API documentation, including the
  anchors.
- **One source for each table.** The command, building-block and platform tables
  are data files: the website renders them, and CI builds its platform matrix
  from the same file. Checked by: A test fails if the command table and the
  binary disagree; the site build fails if a listed item has no tracking issue.
- **Prepared for formal verification.** The core crates are written in the Rust
  subset Aeneas extracts to Lean 4, and a Lean project is built against the
  pinned Aeneas library. Checked by: make check-aeneas and the Lean build, in
  CI.
- **Small reviewed steps.** Features land as stacked pull requests, one
  primitive each, with CI green before the next. Each pull request updates the
  website, and each planned item is tracked by an issue. Checked by: Branch
  protection and review.

## license

MIT
