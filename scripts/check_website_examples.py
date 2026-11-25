#!/usr/bin/env python3
"""Run every command the website shows, so the website cannot drift.

Reads website/src/examples.json and runs the examples in order, in one fresh
directory (later tasks use the files earlier tasks create), exactly as a
reader would paste them into bash:

- every command is displayed as lines of at most MAX_WIDTH characters joined
  by backslash continuations, and runs exactly as displayed;
- every command must succeed with the given OpenSSL as `openssl`;
- each task is also shown with `baldssl` in place of `openssl` (the page's
  toggle); for a task with status "supported" that variant is run, on a copy
  of the directory as it was before the task, and must exit the same way and
  produce the same stdout and the same files, byte for byte;
- a supported task with random output (a new key) is checked by running
  its `verify` commands with OpenSSL on what baldssl produced;
- a deterministic task with status "not-yet" fails the check if baldssl
  already reproduces it, so the status is updated when a feature lands;
- `usage` and `compatibility` commands run with baldssl as `baldssl`;
- `install` commands run only with --install (CI), since they install.

Usage:
  scripts/check_website_examples.py --openssl PATH --baldssl PATH [--install]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "website" / "src" / "examples.json"

# Characters per displayed line: what fits a 375 px phone screen in the
# website's code blocks.
MAX_WIDTH = 38

# The release lines baldssl has a profile of its own for, besides the major
# versions (baldssl_x509::Compat).
LINES = ("3.0", "3.6")

# The program name `openssl`, where the shell runs it.
PROGRAM = re.compile(r"(?<![\w./-])openssl(?= )")


def displayed(lines: list[str]) -> list[str]:
    """Checks the display rules and returns the problems found."""
    problems = []
    for i, line in enumerate(lines):
        if len(line) > MAX_WIDTH:
            problems.append(f"line {i + 1} is {len(line)} characters")
        continued = line.endswith(" \\")
        if continued != (i < len(lines) - 1):
            problems.append(f"line {i + 1}: continuation backslash")
    return problems


def profile(version: str) -> str:
    """The baldssl profile (BALDSSL_OPENSSL_COMPAT) for an OpenSSL version:
    the release line for 3.0 and 3.6, which differ from the rest of 3, and
    the major version otherwise."""
    for line in LINES:
        if version == line or version.startswith(f"{line}."):
            return line
    return version.split(".", maxsplit=1)[0]


def baldssl_variant(command: str) -> str:
    """The command as the website shows it with the toggle on baldssl."""
    return PROGRAM.sub("baldssl", command)


def bin_dir(base: Path, name: str, links: dict[str, Path]) -> Path:
    """A directory holding the given command names as symlinks."""
    d = base / name
    d.mkdir()
    for command, target in links.items():
        (d / command).symlink_to(target)
    return d


def run(
    command: str, cwd: Path, path_first: Path, env_extra: dict[str, str]
) -> subprocess.CompletedProcess[bytes]:
    env = dict(os.environ)
    env["PATH"] = f"{path_first}{os.pathsep}{env['PATH']}"
    env.update(env_extra)
    # The commands are the website's examples, from the repository.
    return subprocess.run(  # noqa: S603
        ["bash", "-o", "pipefail", "-c", command],  # noqa: S607
        cwd=cwd,
        env=env,
        capture_output=True,
        timeout=600,
        check=False,
    )


def snapshot(d: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(d)): p.read_bytes()
        for p in sorted(d.rglob("*"))
        if p.is_file()
    }


def changed(
    before: dict[str, bytes], after: dict[str, bytes]
) -> dict[str, bytes]:
    return {k: v for k, v in after.items() if before.get(k) != v}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--openssl", required=True, type=Path)
    parser.add_argument("--baldssl", required=True, type=Path)
    parser.add_argument("--install", action="store_true")
    args = parser.parse_args()
    openssl = args.openssl.resolve()
    baldssl = args.baldssl.resolve()

    # The binary is the one named on the command line.
    version = subprocess.run(  # noqa: S603
        [str(openssl), "version"], capture_output=True, text=True, check=True
    ).stdout.split()[1]
    line = profile(version)
    environment = {"BALDSSL_OPENSSL_COMPAT": line}
    print(f"OpenSSL {version} (baldssl profile {line})")

    examples = json.loads(EXAMPLES.read_text(encoding="utf-8"))["examples"]
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="baldssl-examples-") as tmp:
        base = Path(tmp)
        work = base / "work"
        work.mkdir()
        real = bin_dir(base, "real", {"openssl": openssl, "baldssl": baldssl})

        for ex in examples:
            ident, section, lines = ex["id"], ex["section"], ex["lines"]
            command = "\n".join(lines)
            for problem in displayed(lines):
                failures.append(f"{ident}: {problem}")
            if section == "install" and not args.install:
                print(f"skip  {ident} (pass --install to run it)")
                continue
            before = snapshot(work)
            shadow = base / f"shadow-{ident}"
            shutil.copytree(work, shadow)

            ran = run(command, work, real, environment)
            if ran.returncode != 0:
                failures.append(
                    f"{ident}: exit {ran.returncode}: "
                    f"{ran.stderr.decode(errors='replace').strip()[:300]}"
                )
                print(f"FAIL  {ident}")
                continue

            status = ex.get("status")
            if section != "tasks" or not (
                status == "supported" or ex.get("deterministic")
            ):
                print(f"ok    {ident}")
                continue

            if status == "supported" and not ex.get("deterministic"):
                # Random output (a new key): baldssl must succeed, and
                # OpenSSL must accept what it produced.
                mine = run(baldssl_variant(command), shadow, real, environment)
                problems = []
                if mine.returncode != 0:
                    problems.append(
                        f"exit {mine.returncode}: "
                        f"{mine.stderr.decode(errors='replace').strip()[:300]}"
                    )
                for check in ex.get("verify", []):
                    verified = run(check, shadow, real, environment)
                    if verified.returncode != 0:
                        problems.append(
                            f"`{check}` rejects it: "
                            f"{verified.stderr.decode(errors='replace').strip()[:300]}"
                        )
                if not ex.get("verify"):
                    problems.append("a random supported task needs `verify`")
                if problems:
                    failures.append(f"{ident}: baldssl " + "; ".join(problems))
                    print(f"FAIL  {ident} (baldssl)")
                else:
                    print(f"ok    {ident} (baldssl verified by OpenSSL)")
                continue

            mine = run(baldssl_variant(command), shadow, real, environment)
            same = (
                mine.returncode == 0
                and mine.stdout == ran.stdout
                and changed(before, snapshot(shadow))
                == changed(before, snapshot(work))
            )
            if status == "supported" and not same:
                failures.append(
                    f"{ident}: baldssl differs from OpenSSL (exit "
                    f"{mine.returncode}: "
                    f"{mine.stderr.decode(errors='replace').strip()[:300]})"
                )
                print(f"FAIL  {ident} (baldssl)")
            elif status != "supported" and same:
                failures.append(
                    f"{ident}: baldssl reproduces OpenSSL; mark it supported "
                    "in website/src/examples.json"
                )
                print(f"FAIL  {ident} (status)")
            else:
                print(
                    f"ok    {ident}" + (" (baldssl identical)" if same else "")
                )

    for f in failures:
        print(f"error: {f}", file=sys.stderr)
    print(f"{len(examples)} examples, {len(failures)} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
