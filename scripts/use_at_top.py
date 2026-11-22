#!/usr/bin/env python3
"""Keeps `use` declarations at the top level of their module.

The project's convention: imports are written at the top of a module (a
file, or an inline `mod name { ... }`), never inside a function or another
block, so a module's dependencies are read in one place.

A `use` written after a brace on the same line (`fn f() { use x; }`) is not
seen; rustfmt never formats code that way.

Usage: use_at_top.py FILE...   exits 1 and lists the offending lines.
"""

import re
import sys
from pathlib import Path

MOD_OPEN = re.compile(r"^\s*(pub(\([^)]*\))?\s+)?mod\s+\w+\s*\{\s*$")
USE = re.compile(r"^\s*(pub(\([^)]*\))?\s+)?use\s")


def strip(line: str) -> str:
    """The line without string literals and comments, for brace counting."""
    line = re.sub(r'"(\\.|[^"\\])*"', '""', line)
    line = re.sub(r"'(\\.|[^'\\])'", "''", line)
    return line.split("//", 1)[0]


def check(path: str) -> list[str]:
    errors = []
    # One entry per open brace: True when it opened a module.
    stack: list[bool] = []
    with Path(path).open(encoding="utf-8") as f:
        for number, line in enumerate(f, 1):
            code = strip(line)
            if USE.match(code) and not all(stack):
                errors.append(f"{path}:{number}: `use` inside a block")
            is_mod = bool(MOD_OPEN.match(code))
            for char in code:
                if char == "{":
                    stack.append(is_mod)
                    is_mod = False
                elif char == "}" and stack:
                    stack.pop()
    return errors


def main() -> int:
    errors = [e for path in sys.argv[1:] for e in check(path)]
    for error in errors:
        print(error)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
