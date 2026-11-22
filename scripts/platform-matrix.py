#!/usr/bin/env python3
"""Prints the CI matrices of the os-rng jobs from website/src/platforms.json.

One line per job, `<name>=<JSON list>`, the format of $GITHUB_OUTPUT; each
job reads its line with `fromJSON(needs.platforms.outputs.<name>)`. The same
file feeds the website's Platforms table, so the versions CI tests and the
versions the website lists cannot drift apart.

Exits 1 when an entry misses a field its job needs.

Usage: platform-matrix.py [path/to/platforms.json]
"""

import json
import sys
from pathlib import Path

DEFAULT = Path(__file__).resolve().parent.parent / "website/src/platforms.json"

# The fields each job reads, per platform id; macOS and Windows share a job.
FIELDS = {
    "glibc": ("glibc", ["name", "image", "expect"]),
    "musl": ("musl", ["name", "target", "runner"]),
    "android": ("android", ["name", "mode", "api"]),
    "macos": ("runners", ["name", "runner"]),
    "windows": ("runners", ["name", "runner"]),
    "bsd": ("bsd", ["name", "os", "release"]),
}
EXPECT = {"pass", "link-fail"}


def matrices(data):
    """{job: [entries]} and the list of problems found."""
    out, problems = {}, []
    for platform in data["platforms"]:
        pid = platform.get("id")
        if pid not in FIELDS:
            problems.append(f"unknown platform id {pid!r}")
            continue
        job, needed = FIELDS[pid]
        for version in platform.get("versions", []):
            missing = [f for f in needed if f not in version]
            if missing:
                problems.append(f"{pid}: {version.get('name')}: no {missing}")
            if version.get("expect") not in EXPECT:
                problems.append(
                    f"{pid}: {version.get('name')}: expect must be one of "
                    f"{sorted(EXPECT)}"
                )
            out.setdefault(job, []).append(version)
    return out, problems


def main(argv):
    path = Path(argv[0]) if argv else DEFAULT
    out, problems = matrices(json.loads(path.read_text(encoding="utf-8")))
    if problems:
        for p in problems:
            print(f"platforms.json: {p}", file=sys.stderr)
        return 1
    for job, entries in sorted(out.items()):
        print(f"{job}={json.dumps(entries, separators=(',', ':'))}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
