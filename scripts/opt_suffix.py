#!/usr/bin/env python3
"""Keeps the `_opt` suffix on functions that return an `Option`.

The project's convention: a function or method that can fail returns a
`Result` with the reason under its plain name (`decode`); one that returns an
`Option` instead is named with the `_opt` suffix (`decode_opt`). Methods of
standard-library traits (`partial_cmp`, `next`) keep their names. This fails on
every `fn` whose return type is an `Option` and whose name does not end in
`_opt`. The parameters are skipped by matching parentheses, so an `Option` in
a parameter's type (a function pointer) is not mistaken for the return type.

Usage: opt_suffix.py FILE...   exits 1 and lists the offending functions.
"""

import re
import sys
from pathlib import Path

# Methods of standard-library traits, whose names are fixed by the trait.
STD_TRAIT_METHODS = {"partial_cmp", "next", "next_back", "nth", "last"}

FN = re.compile(r"\bfn\s+([a-z_][a-z0-9_]*)\s*(<[^{;]*?>)?\s*\(")


def returns_option(text: str, open_paren: int) -> bool:
    """Whether the signature whose parameters open at `open_paren` returns
    an `Option`."""
    depth = 0
    i = open_paren
    while i < len(text):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                break
        i += 1
    return re.match(r"\s*->\s*Option\s*<", text[i + 1 :]) is not None


def check(path: str) -> list[str]:
    text = Path(path).read_text(encoding="utf-8")
    errors = []
    for m in FN.finditer(text):
        name = m.group(1)
        if name.endswith("_opt") or name in STD_TRAIT_METHODS:
            continue
        if returns_option(text, m.end() - 1):
            line = text.count("\n", 0, m.start()) + 1
            errors.append(
                f"{path}:{line}: `{name}` returns an Option: `{name}_opt`"
            )
    return errors


def main() -> int:
    errors = [e for path in sys.argv[1:] for e in check(path)]
    for error in errors:
        print(error)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
