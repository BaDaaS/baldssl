#!/usr/bin/env python3
"""Generate website/src/commands.json: every command OpenSSL provides, with
its description and baldssl's support status.

The command lists come from `openssl list -1 -commands` (and the digest and
cipher shortcut commands) of two OpenSSL binaries, the descriptions from the
NAME section of their manual pages. The `status` and `note` fields are owned
by humans: regenerating preserves them, and new commands start as
"not-started".

Status values:
  supported    implemented and byte-for-byte compatible
  partial      implemented for a subset of the options (see note)
  planned      next on the roadmap
  not-started  nothing yet

Usage: scripts/gen-commands.py <openssl-3.5> <openssl-4.1> <out.json>
"""
import gzip
import json
import os
import re
import subprocess
import sys

STATUSES = ("supported", "partial", "planned", "not-started")

# Commands without a manual page of their own, described from openssl(1).
FALLBACK = {"help": "Display information about a command's options"}


def run(openssl, *args):
    out = subprocess.run([openssl, *args], capture_output=True, text=True,
                         check=True).stdout
    return [line.strip() for line in out.splitlines() if line.strip()]


def man_dir(openssl):
    return os.path.join(os.path.dirname(os.path.dirname(
        os.path.realpath(openssl))), "share", "man", "man1")


def description(openssl, name):
    """The text after ' - ' in the NAME section of openssl-<name>(1)."""
    for stem in (f"openssl-{name}", name):
        for ext in (".1ssl.gz", ".1ssl", ".1.gz", ".1"):
            path = os.path.join(man_dir(openssl), stem + ext)
            if not os.path.exists(path):
                continue
            opener = gzip.open if path.endswith(".gz") else open
            with opener(path, "rt", encoding="utf-8") as fh:
                text = fh.read()
            m = re.search(r'^\.SH "?NAME"?\s*\n(.*?)\n\.', text, re.S | re.M)
            if not m:
                continue
            line = " ".join(m.group(1).split()).replace("\\-", "-")
            line = re.sub(r"\\f[BIRP]", "", line)
            if " - " in line:
                return line.split(" - ", 1)[1].strip()
    return None


def main():
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    old_bin, new_bin, out_path = sys.argv[1:]
    versions = {}
    for label, binary in (("3.5", old_bin), ("4.1", new_bin)):
        version = run(binary, "version")[0].split()[1]
        if not version.startswith(label):
            print(f"{binary} is {version}, expected {label}", file=sys.stderr)
            return 1
        versions[label] = binary

    previous = {}
    if os.path.exists(out_path):
        with open(out_path, encoding="utf-8") as fh:
            for entry in json.load(fh)["commands"]:
                previous[(entry["kind"], entry["name"])] = entry

    entries = {}
    for label, binary in versions.items():
        for kind, flag in (("standard", "-commands"),
                           ("digest", "-digest-commands"),
                           ("cipher", "-cipher-commands")):
            for name in run(binary, "list", "-1", flag):
                e = entries.setdefault((kind, name), {
                    "name": name, "kind": kind, "openssl": [],
                    "description": None,
                })
                e["openssl"].append(label)
                if kind == "standard":
                    e["description"] = (description(binary, name)
                                        or e["description"])
                elif kind == "digest":
                    e["description"] = f"Shortcut for `dgst -{name}`"
                else:
                    e["description"] = f"Shortcut for `enc -{name}`"

    commands = []
    order = {"standard": 0, "digest": 1, "cipher": 2}
    for key in sorted(entries, key=lambda k: (order[k[0]], k[1])):
        e = entries[key]
        prev = previous.get(key, {})
        status = prev.get("status", "not-started")
        if status not in STATUSES:
            raise SystemExit(f"{e['name']}: unknown status {status!r}")
        e["description"] = (e["description"] or FALLBACK.get(e["name"])
                            or "(no manual page)")
        e["status"] = status
        e["note"] = prev.get("note", "")
        commands.append(e)

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write('{\n  "openssl": ["3.5", "4.1"],\n  "commands": [\n')
        # One object per line: diff-friendly, and parsed line by line by
        # crates/baldssl/tests/commands.rs.
        fh.write(",\n".join("    " + json.dumps(c, ensure_ascii=True)
                            for c in commands))
        fh.write("\n  ]\n}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
