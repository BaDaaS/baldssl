#!/usr/bin/env python3
"""Checks that the README's "Engineering practices" list and the website's
(website/src/practices.json) name the same practices, in the same order.

Usage: check_practices.py README.md website/src/practices.json
"""

import json
import re
import sys


def readme_titles(path: str) -> list[str]:
    text = open(path, encoding="utf-8").read()
    match = re.search(r"^## Engineering practices\n(.*?)(?=^## )", text, re.S | re.M)
    if not match:
        return []
    return re.findall(r"^- \*\*(.+?)\.\*\*", match.group(1), re.M)


def main() -> int:
    readme, data = sys.argv[1], sys.argv[2]
    site = [p["title"] for p in json.load(open(data, encoding="utf-8"))["practices"]]
    ours = readme_titles(readme)
    if ours != site:
        print(f"{readme} and {data} list different practices:")
        print(f"  README:  {ours}")
        print(f"  website: {site}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
