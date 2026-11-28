#!/usr/bin/env python3
"""Prints which groups of CI jobs a change needs, from the files it changes.

Reads the changed paths, one per line, from the file given (`git diff
--name-only` output), and prints one line per group, `<group>=true` or
`<group>=false`, the format of $GITHUB_OUTPUT; each job of .github/workflows/
ci.yml runs only `if: needs.changes.outputs.<group> == 'true'`. With `--all`,
every group is true: a push to main runs everything.

A group is true when a changed path matches one of its patterns, or one of
EVERYTHING: a change to the workflow, the Makefile or these rules can change
what any job does. A pattern is an fnmatch pattern, in which `*` also matches
`/`, so `crates/*` is everything under crates/.

Usage: ci-changes.py (CHANGED_FILES | --all)
"""

import sys
from fnmatch import fnmatchcase
from pathlib import Path

# A change to one of these can change what any job does.
EVERYTHING = (
    ".github/workflows/ci.yml",
    "Makefile",
    "scripts/ci-changes.py",
)

# What every Rust build reads: the sources, the manifests, the toolchain and
# the lints, and the tests with their fixtures.
RUST = (
    "crates/*",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "clippy.toml",
    ".cargo/*",
    "tests/*",
)

# The OpenSSL builds the interop, website and golden jobs use.
OPENSSL_BUILD = (".github/actions/build-openssl/*",)

GROUPS: dict[str, tuple[str, ...]] = {
    # test, cross, wasm, coverage and profiles: build and test the workspace.
    "rust": RUST,
    # platforms and the os-rng jobs: os_rng, and the versions they test.
    "os-rng": (
        "crates/baldssl-crypto/*",
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        ".cargo/*",
        "website/src/platforms.json",
        "scripts/platform-matrix.py",
        "scripts/test-os-rng-*",
    ),
    # format: rustfmt, taplo and prettier.
    "format": ("*.rs", "*.toml", "*.md", ".prettierrc.json", ".prettierignore"),
    # hygiene: the source checks, the docs, the aeneas build, shellcheck.
    "hygiene": (
        *RUST,
        "fuzz/*",
        "scripts/*",
        "README.md",
        "website/src/practices.json",
    ),
    # python: the scripts' formatting, lints, types and tests.
    "python": ("scripts/*.py", "pyproject.toml", "uv.lock"),
    # links: every URL in the sources and the rendered docs.
    "links": (
        *RUST,
        "fuzz/*",
        "scripts/*",
        "*.md",
        ".github/*",
        "website/index.html",
        "website/src/*",
    ),
    # interop: baldssl against OpenSSL, through the interop scripts.
    "interop": (
        *RUST,
        *OPENSSL_BUILD,
        "scripts/*interop*.sh",
        "scripts/find-openssl.sh",
        "scripts/gen-certs.sh",
    ),
    # website-examples: every command the website shows.
    "website-examples": (
        *RUST,
        *OPENSSL_BUILD,
        "website/src/examples.json",
        "scripts/check_website_examples.py",
    ),
    # golden: OpenSSL's output against the pinned fixtures (no baldssl).
    "golden": (
        *OPENSSL_BUILD,
        "tests/fixtures.mk",
        "scripts/fetch-fixtures.sh",
        "scripts/gen-*",
    ),
    # lean: the Lean 4 skeleton.
    "lean": ("proofs/*",),
}


def needed(paths: list[str]) -> dict[str, bool]:
    """{group: whether a path in `paths` asks for it}."""

    def hits(patterns: tuple[str, ...]) -> bool:
        return any(fnmatchcase(p, pat) for p in paths for pat in patterns)

    everything = hits(EVERYTHING)
    return {g: everything or hits(pats) for g, pats in GROUPS.items()}


def main(argv: list[str]) -> int:
    if argv == ["--all"]:
        groups = dict.fromkeys(GROUPS, True)
    elif len(argv) == 1:
        text = Path(argv[0]).read_text(encoding="utf-8")
        groups = needed([line for line in text.splitlines() if line])
    else:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    for group, value in groups.items():
        print(f"{group}={'true' if value else 'false'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
