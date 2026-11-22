#!/usr/bin/env python3
"""Keeps trait bounds on type parameters in `where` clauses.

The project's convention: a type parameter is declared bare
and refined in a `where` clause, never inline:

    impl<C> Affine<C> where C: ShortWeierstrass { ... }     # yes
    impl<C: ShortWeierstrass> Affine<C> { ... }             # no

Without --fix, lists every inline bound in the given Rust files and exits 1
if there is one. With --fix, moves each to the item's `where` clause
(creating it, or prepending to an existing one); run rustfmt afterwards.

Covered: the generic parameter lists of fn, struct, enum, union, impl and
trait. Not bounds: const parameters (`const N: usize` declares a type),
lifetimes, and supertraits (`trait A: B` declares inheritance). Comments,
strings and char literals are skipped.

Usage: where_clauses.py [--fix] FILE...
"""

import re
import sys

KEYWORDS = ("fn", "struct", "enum", "union", "impl", "trait")
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def code_mask(src):
    """True for each character that is code (not comment or literal)."""
    mask = [True] * len(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            mask[i:j] = [False] * (j - i)
            i = j
        elif src.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif src.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            mask[i:j] = [False] * (j - i)
            i = j
        elif c == '"' or (c == "r" and re.match(r'r#*"', src[i:])):
            m = re.match(r'r(#*)"', src[i:]) if c == "r" else None
            if m:
                end = src.find('"' + m.group(1), i + len(m.group(0)))
                j = n if end < 0 else end + 1 + len(m.group(1))
            else:
                j = i + 1
                while j < n and src[j] != '"':
                    j += 2 if src[j] == "\\" else 1
                j += 1
            mask[i:j] = [False] * (j - i)
            i = j
        elif c == "'":
            # A char literal, or a lifetime (left as code).
            m = re.match(r"'(\\.|\\u\{[0-9a-fA-F]+\}|[^\\'])'", src[i:])
            if m:
                j = i + len(m.group(0))
                mask[i:j] = [False] * (j - i)
                i = j
            else:
                i += 1
        else:
            i += 1
    return mask


def close_angle(src, mask, start):
    """Index of the `>` closing the `<` at `start`."""
    depth, i = 0, start
    while i < len(src):
        if mask[i]:
            c = src[i]
            if c in "<([":
                depth += 1
            elif c == ">" and src[i - 1] != "-":
                depth -= 1
                if depth == 0:
                    return i
            elif c in ")]":
                depth -= 1
        i += 1
    raise ValueError(f"unclosed < at {start}")


def split_top(text):
    """Splits a generic list at its top-level commas."""
    parts, depth, cur = [], 0, ""
    for k, c in enumerate(text):
        if c in "<([":
            depth += 1
        elif c == ">" and (k == 0 or text[k - 1] != "-"):
            depth -= 1
        elif c in ")]":
            depth -= 1
        if c == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += c
    if cur.strip():
        parts.append(cur)
    return parts


def body_start(src, mask, i):
    """Where the item's signature ends: the index of its `where`, or of the
    `{` or `;` that follows it, at depth 0. Returns (index, has_where)."""
    depth = 0
    while i < len(src):
        if mask[i]:
            c = src[i]
            if c in "([":
                depth += 1
            elif c in ")]":
                depth -= 1
            elif c == "<":
                depth += 1
            elif c == ">" and src[i - 1] != "-":
                depth -= 1
            elif depth == 0 and c in "{;":
                return i, False
            elif (depth == 0 and src.startswith("where", i)
                  and not (src[i - 1].isalnum() or src[i - 1] == "_")
                  and not (src[i + 5:i + 6].isalnum())):
                return i, True
        i += 1
    raise ValueError("no body")


def generic_lists(src):
    """(keyword index, '<' index, '>' index) of each item's generics."""
    mask = code_mask(src)
    for m in re.finditer(r"\b(" + "|".join(KEYWORDS) + r")\b", src):
        if not mask[m.start()]:
            continue
        i = m.end()
        while i < len(src) and src[i].isspace():
            i += 1
        if m.group(1) != "impl":
            ident = IDENT.match(src, i)
            if not ident:
                continue  # `fn(u8) -> u8`, `impl Trait`, ...
            i = ident.end()
            while i < len(src) and src[i].isspace():
                i += 1
        if i < len(src) and src[i] == "<" and mask[i]:
            yield m.start(), i, close_angle(src, mask, i), mask


def inline_bounds(params):
    """[(index, name, bounds)] of the parameters bounded inline."""
    out = []
    for k, p in enumerate(split_top(params)):
        p = p.strip()
        if p.startswith(("const ", "'")) or ":" not in p or "=" in p:
            continue
        name, bounds = p.split(":", 1)
        out.append((k, name.strip(), " ".join(bounds.split())))
    return out


def fix(src):
    """Moves every inline bound to a where clause; returns the new text."""
    while True:
        for _kw, lt, gt, mask in generic_lists(src):
            params = src[lt + 1:gt]
            bounded = inline_bounds(params)
            if not bounded:
                continue
            names = {k: name for k, name, _ in bounded}
            parts = split_top(params)
            bare = ", ".join(
                names.get(k, p.strip()) for k, p in enumerate(parts)
            )
            preds = ", ".join(f"{n}: {b}" for _, n, b in bounded)
            at, has_where = body_start(src, mask, gt + 1)
            if has_where:
                after = at + len("where")
                rest = src[after:]
                new_tail = f" {preds},{rest}"
                src = src[:lt + 1] + bare + src[gt:after] + new_tail
            else:
                head = src[gt:at].rstrip()
                src = (src[:lt + 1] + bare + head + f"\nwhere\n    {preds},\n"
                       + src[at:])
            break
        else:
            return src


def main(argv):
    do_fix = "--fix" in argv
    files = [a for a in argv if a != "--fix"]
    found = 0
    for path in files:
        with open(path, encoding="utf-8") as f:
            src = f.read()
        if do_fix:
            new = fix(src)
            if new != src:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(new)
                print(f"fixed {path}")
            continue
        for _kw, lt, gt, _mask in generic_lists(src):
            for _, name, bounds in inline_bounds(src[lt + 1:gt]):
                line = src.count("\n", 0, lt) + 1
                print(f"{path}:{line}: bound `{name}: {bounds}` belongs in a "
                      "where clause")
                found += 1
    if found:
        print(f"{found} inline bound(s); fix with "
              "`scripts/where_clauses.py --fix FILE...` then rustfmt")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
