# AGENTS.md

Rules for agents (and people) changing baldssl. The README's "Engineering
practices" says what the project does; this file says how to work in it.

## Before you start

- Read the open review comments on the pull request you are continuing,
  including comments on individual commits, and address them first.
- Work happens in small stacked pull requests: one primitive or one command
  each, CI green before the next. Every pull request closes an issue
  (`Closes #N`) and updates the website (`website/src/*.json`) when it changes
  what baldssl does.

## Code

- No new dependency, ever, without the maintainers' approval.
  `make check-no-deps` enforces it for build and run time.
- `unsafe` only in `baldssl-crypto`'s `os_rng` (`make check-unsafe`).
- Trait bounds go in `where` clauses (`make check-where-clauses`), and `use`
  declarations at the top of their module, never inside a function.
- Model structures as traits that compose: a trait has the traits it needs as
  supertraits (a projective model is a constant-time group). A plain `impl`
  holds only what is specific to one type.
- Constant-time code takes `Choice`, never `bool`, and never branches or indexes
  on secret data. Name the property: `_ct` for constant time, `_vartime` for
  variable time.
- Export only what a caller needs; everything else is `pub(crate)` or private.
- No `unwrap`, `expect`, `panic!` or slice indexing in library code; return an
  error.

## Documentation

- Documentation states what the code does now. No plans, no "for now", no
  "will".
- Never mention an issue or a pull request in code or comments; describe the
  design on its own terms.
- Every standard, paper or formula cited links its source, down to the section
  (`make check-urls`).
- Every encoding says its byte order (big-endian or little-endian) and its
  length.
- Say what every acronym stands for where a document first uses it (PEM,
  Privacy-Enhanced Mail; DER, Distinguished Encoding Rules), and once per
  crate in its top-level documentation, with a link to the defining standard.
- ASCII only.

## Tests

- State each structure's laws in its documentation and test each as a property
  (`algebra::laws`), for every implementation.
- Known answers come from the standards or from OpenSSL, never from baldssl's
  own output.
- Decoders are canonical: test that whatever decodes re-encodes to the same
  bytes, and test each rejection rule.
- Output must match OpenSSL byte for byte. Run `make interop` against a real
  OpenSSL (`OPENSSL=/path/to/openssl`): macOS's `/usr/bin/openssl` is LibreSSL,
  which differs.

## Before pushing

- `make ci` and `make check-urls` pass.
- Commit messages: a title under 80 characters and a wrapped body; no co-author
  or tool attribution lines.
