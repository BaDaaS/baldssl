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
- When a pull request below in the stack merges, rebase the next one onto
  `main`: drop the commits already merged (they come back with other hashes),
  retarget its base, remove its "Stacked on" line, and run `make interop`
  against the release lines its changes touch.

## Code

- No new dependency, ever, without the maintainers' approval.
  `make check-no-deps` enforces it for build and run time.
- `unsafe` only in `baldssl-crypto`'s `os_rng` (`make check-unsafe`).
- Trait bounds go in `where` clauses (`make check-where-clauses`), and `use`
  declarations at the top of their module, never inside a function.
- Model structures as traits that compose: a trait has the traits it needs as
  supertraits (a projective model is a constant-time group). A plain `impl`
  holds only what is specific to one type.
- An operation on a value is a method of the value, or of a trait it implements,
  not a free function that takes it (`request.to_text(compat)`, not
  `print_request_text(&request, compat)`). An action a third party performs on a
  value (signing it, issuing it) is a trait of that party.
- Behaviour several types share is a trait (`Encodable`, `Pem`, `Text`); what
  follows from it is an extension trait with a blanket impl (`WritePem` for
  every `Pem`), not a copy per type.
- Use the standard library's vocabulary where it fits: a conversion is `From` or
  `TryFrom` (`Algorithm: TryFrom<&RawTlv>`), a name parses with `FromStr`, a
  text form is `Display`, a sink is `io::Write`. Where it does not fit, the
  documentation says why (`Text` gives bytes and fails with a reason, which
  `Display` cannot).
- Take and return the type a value has, never its raw bytes when a type exists:
  a DER element is a `RawTlv` or a `Tlv`, not a `&[u8]` or a `Vec<u8>`.
- Encodings and text forms do no I/O. Reading and writing files lives in
  `baldssl-fs`, generic over `io::Write`; who may read a file is decided where
  it is opened (`create_owner_only`). A module holds one concern: no file
  handling in a command's key generation, no printing in a parser.
- Every magic number and magic string has a named `const` (or an enum
  discriminant) whose documentation says what it is and where it comes from: the
  standard and its section, or the OpenSSL source file. Code uses the name,
  never the literal (`HANDLED_CRITICAL`, `civil::DAYS_PER_ERA`,
  `VERIFY_FAILED`).
- Identifiers compare as values, never as text: match an `Oid` against
  `ObjectId` constants (`e.oid == ID_CE_KEY_USAGE`), and convert with `From`.
  Dotted text is for messages and tests only.
- Codes and categories are enums, not integers: what OpenSSL returns as `0`,
  `1`, `3` or `4` (`X509_check_ca`) is a `CaKind`, and an enum mirroring
  OpenSSL's numbers carries them as discriminants (`#[repr(u32)]`).
- A value with named parts that crosses a function boundary is a struct, not a
  tuple (`Reported { error, depth }`, not `(VerifyError, usize)`).
- No `Result<Result<..>>`. An early exit that is not a failure of the function
  (verification ends here) shares one type with the errors, with a `From` impl,
  so that `?` serves both; the public result is an enum of the outcomes
  (`Verification::Verified` or `Verification::Failed`).
- A structure is decoded once, into its type, and reused. A second decoder of
  the same structure exists only with the reason in its documentation (the
  `-text` printer accepts the malformed values OpenSSL prints, which the typed
  decoding refuses).
- A command returns what it writes on standard output and never writes standard
  output itself; a failure that has output carries it
  (`Error::Reported { code, output }`).
- A difference between OpenSSL release lines is an item of
  `baldssl_x509::Profile` named for what differs (`Profile::NOT_YET_VALID`,
  `Profile::CERTIFICATE_TIMES`), whose documentation cites the OpenSSL source
  that differs; its default is what the lines share, and each line's type
  overrides it where it differs. Code that depends on the line is generic over
  `P: Profile`. A difference of OpenSSL's applications (`apps/`: messages,
  option parsing, what a command writes) is an item of the CLI's `line::Apps` in
  the same way (`Apps::LOAD_MESSAGE`). Callers ask the item; they never compare
  lines (`compat != Compat::V4`), which silently puts a new line on one side.
  `Compat` is the line as a value, for `Compat::run` and for tests that pick a
  known answer by line.
- Before an OpenSSL release joins CI, diff the sources baldssl reproduces
  (`apps/*.c`, the message tables such as `crypto/x509/x509_txt.c`) against the
  release line it would share a profile with; any difference that reaches
  baldssl's output gets its own profile.
- Command-line arguments that are data (keys, passphrases, values) are bytes,
  taken with `as_encoded_bytes()`, as OpenSSL takes them. `to_string_lossy()` is
  for messages only: it replaces what is not UTF-8.
- A fallback value (`unwrap_or(0)`, `map_or(0, ..)`, `unwrap_or_default()`) says
  in a comment why it cannot give a wrong result, or the code returns an error
  instead.
- No `bool` parameter or field selects behaviour: an enum names each case. Where
  OpenSSL's flags are sticky (no later option clears them), the enum's order
  models that and the value is the maximum given, with a test of the option
  orders.
- One source per list: a list of names (commands, digests, extensions) is
  written once, and everything else derives from it (`Algorithm::ALL`).
- Every variant of an outcome enum (what checking, verifying or processing
  gives) is reached by a test.
- Parse, don't validate: a value of a type is proof that it is valid. A
  validated type keeps its fields private and has one fallible constructor at
  the boundary (`TryFrom`, `FromStr`, or a `const fn` that asserts at compile
  time, as `ObjectId::from_static` does); what takes the type is then total.
- A `match` on an enum of baldssl's lists its variants, so that adding one is a
  compile error wherever it needs a decision (`clippy::wildcard_enum_match_arm`
  denies `_ =>`); a variant is never singled out with `==` or `!=` where a
  `match` would ask for every case.
- No `as` converts integers (`clippy::as_conversions` denies it): use `From` or
  `TryFrom`, or, in `const` code and for branch-free truncations on secret data,
  the documented conversions of `baldssl_core::num`, the one place `as`
  converts. Reading an enum's discriminant is the exception, in one documented
  method of that enum with its `allow`. Arithmetic that can overflow is
  `checked_*` or `saturating_*`, with the reason saying which.
- A run-time choice among a closed set of types is an enum with one eliminator,
  the only place the run-time name becomes a type (`Algorithm::with`); every
  operation goes through it rather than repeating the `match`.
- Secret material (private keys, seeds, MAC keys, passphrases) lives in a type
  that is not `Copy`, shows nothing of its contents in `Debug` or `Display`, is
  wiped when dropped, and compares in constant time (`SecretBytes`).
- A parser returns a view that borrows its input (`Tlv<'a>`, `Certificate<'a>`);
  what builds a value owns it (`RawTlv`, `ObjectId`). A view becomes an owned
  value through `From`, never through its text or a re-encoding.
- A trait whose laws baldssl relies on to verify, sign or encode is sealed, so
  that no implementation outside the crate can break them.
- An outcome enum and a function returning `Result` are `#[must_use]`, and a
  `let _ =` on a `Result` says in a comment why the result does not matter.
- Push a precondition into a type so the operation is total
  (`RawTlv::from_tag_and_contents` is total, as every tag and contents form one
  TLV); an operation that stays partial says so by its `_opt` suffix, and its
  documentation states its exact domain.
- A claim that a result is the best, the only or the first (the issuer chain
  building prefers) comes with a witness: the code returns it, or a test shows
  that no other candidate does better.
- Constant-time code takes `Choice`, never `bool`, and never branches or indexes
  on secret data. Name the property: `_ct` for constant time, `_vartime` for
  variable time.
- A function or method that can fail returns a `Result` with the reason under
  its plain name (`decode`, `from_secret`); one that returns an `Option` instead
  carries the `_opt` suffix (`decode_opt`, `from_dotted_opt`).
- Export only what a caller needs; everything else is `pub(crate)` or private.
- No `unwrap`, `expect`, `panic!` or slice indexing in library code; return an
  error.
- An `allow` silences one lint and says why: one attribute per lint, each with
  its own `reason = "..."`, specific to that lint at that place.
- Python scripts under `scripts/` use the standard library only, pass ruff and
  mypy in strict mode, and a script that checks something has tests of its rule
  in `scripts/tests` (`make check-py`; the tools are pinned in `uv.lock`).

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
  Privacy-Enhanced Mail; DER, Distinguished Encoding Rules), and once per crate
  in its top-level documentation, with a link to the defining standard.
- ASCII only.

## Tests

- State each structure's laws in its documentation and test each as a property
  (`algebra::laws`), for every implementation.
- Known answers come from the standards or from OpenSSL, never from baldssl's
  own output.
- Decoders are canonical: test that whatever decodes re-encodes to the same
  bytes, and test each rejection rule.
- An operation that combines values (a merge, an override, a maximum) names its
  algebra in its documentation and tests its laws as properties: associativity,
  idempotence, the identity, and commutativity when it holds
  (`Extensions::override_with` is a band, a role taken at its maximum a
  join-semilattice).
- Two representations of one thing commute with their operations: a conversion
  between them (a view and an owned value, a run-time name and its type) is
  tested on the square, converting then operating against operating then
  converting (a `Tlv` view and the `RawTlv` made from it encode the same bytes).
- A run-time dispatch over a closed set is tested equal to the typed path for
  every member (`Algorithm::digest` against the hash type each `Algorithm`
  names).
- Every decoder says which map it is: the inverse of its encoder on the
  encoder's image, with the canonicity law; or a lenient reader that accepts
  more than its encoder writes, with the reason (the `-text` printer prints the
  malformed values OpenSSL prints) and a test of where the two differ.
- Output must match OpenSSL byte for byte. Run `make interop` against a real
  OpenSSL (`OPENSSL=/path/to/openssl`): macOS's `/usr/bin/openssl` is LibreSSL,
  which differs.

## Bugs in OpenSSL

- When OpenSSL does something its documentation, its own code's evident intent
  or the standard it implements says it should not (a bug, not a choice), warn
  the maintainers at once, and open an issue for it: what OpenSSL does, a
  reproducer with the releases it was run against, the source that causes it,
  and what baldssl does about it.
- Until the maintainers decide otherwise, baldssl reproduces the bug, as the
  byte-for-byte rule asks, and its code says where and why.

## Before pushing

- `make ci` and `make check-urls` pass.
- Every commit builds and passes clippy on its own. A review fix goes into the
  commit that introduced the code (`git commit --fixup` and
  `git rebase --autosquash`), and a commit message that names something renamed
  or removed is reworded.
- When a review flags a pattern, fix the class, not the instance: search the
  pull request, and the stack above it, for every other occurrence before
  pushing.
- Commit messages: a title under 80 characters and a wrapped body; no co-author
  or tool attribution lines.

## Comments

- Every comment an agent posts (on a pull request, a review, an issue, or a
  reply in a thread) MUST disclose that it was written by AI: it ends with a
  line naming the model and the tool, such as
  `Generated by Claude (Opus 5.5) with Claude Code.` This applies to comments,
  not to commit messages, which carry no attribution (see above).
