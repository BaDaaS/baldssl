#!/usr/bin/env python3
"""Run every command the website shows, so the website cannot drift.

Reads website/src/examples.json and runs the examples in order, in one fresh
directory (later tasks use the files earlier tasks create), exactly as a
reader would paste them into bash:

- every command must succeed with the given OpenSSL as `openssl`;
- a task with status "supported" is also run with baldssl as `openssl`, on a
  copy of the directory as it was before the task, and must exit the same way
  and produce the same stdout and the same files, byte for byte;
- a deterministic task with status "not-yet" fails the check if baldssl
  already reproduces it, so the status is updated when a feature lands;
- `usage` and `compatibility` commands run with baldssl as `baldssl`;
- `install` commands run only with --install (CI), since they install.

Usage:
  scripts/check-website-examples.py --openssl PATH --baldssl PATH [--install]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "website" / "src" / "examples.json"


def bin_dir(base: Path, name: str, links: dict[str, Path]) -> Path:
    """A directory holding the given command names as symlinks."""
    d = base / name
    d.mkdir()
    for command, target in links.items():
        (d / command).symlink_to(target)
    return d


def run(command: str, cwd: Path, path_first: Path, env_extra: dict[str, str]):
    env = dict(os.environ)
    env["PATH"] = f"{path_first}{os.pathsep}{env['PATH']}"
    env.update(env_extra)
    return subprocess.run(
        ["bash", "-o", "pipefail", "-c", command],
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


def changed(before: dict[str, bytes], after: dict[str, bytes]) -> dict[str, bytes]:
    return {k: v for k, v in after.items() if before.get(k) != v}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--openssl", required=True, type=Path)
    parser.add_argument("--baldssl", required=True, type=Path)
    parser.add_argument("--install", action="store_true")
    args = parser.parse_args()
    openssl = args.openssl.resolve()
    baldssl = args.baldssl.resolve()

    version = subprocess.run(
        [str(openssl), "version"], capture_output=True, text=True, check=True
    ).stdout.split()[1]
    profile = {"BALDSSL_OPENSSL_COMPAT": version.split(".")[0]}
    print(f"OpenSSL {version} (baldssl profile {profile['BALDSSL_OPENSSL_COMPAT']})")

    examples = json.loads(EXAMPLES.read_text(encoding="utf-8"))["examples"]
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="baldssl-examples-") as tmp:
        base = Path(tmp)
        work = base / "work"
        work.mkdir()
        real = bin_dir(base, "real", {"openssl": openssl, "baldssl": baldssl})
        dropin = bin_dir(base, "dropin", {"openssl": baldssl, "baldssl": baldssl})

        for ex in examples:
            ident, section, command = ex["id"], ex["section"], ex["command"]
            if section == "install" and not args.install:
                print(f"skip  {ident} (pass --install to run it)")
                continue
            before = snapshot(work)
            shadow = base / f"shadow-{ident}"
            shutil.copytree(work, shadow)

            ran = run(command, work, real, profile)
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

            mine = run(command, shadow, dropin, profile)
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
                print(f"ok    {ident}" + (" (baldssl identical)" if same else ""))

    for f in failures:
        print(f"error: {f}", file=sys.stderr)
    print(f"{len(examples)} examples, {len(failures)} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
