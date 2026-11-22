#!/usr/bin/env python3
"""Checks that every URL in the sources and in the rendered docs is reachable.

Collects http(s) URLs from the given files and directories: comments of Rust
files, Markdown, HTML (including the rustdoc output in target/doc), JSON,
YAML and shell scripts. Each distinct URL is fetched (GET, redirects
followed, a few retries on 429, 5xx and timeouts); a status below 400 is
reachable. When the URL has a fragment and the page is HTML, the fragment
must name an element of the page (`id="..."` or `name="..."`), so a link to
`rfc8032#section-5.1` fails if the section is renumbered.

Exceptions, each with its reason:
- links rustdoc generates to doc.rust-lang.org are skipped: they are not
  written by hand, and there are thousands;
- a few hosts answer scripts with 403 although the page exists; for those
  only, 403 counts as reachable (see BLOCKS_SCRIPTS);
- fragments on github.com are not checked: GitHub renders anchors such as
  line numbers with JavaScript.

Exits 1 when a URL is unreachable or a fragment is missing.

Usage: check_urls.py PATH...
"""

import concurrent.futures
import html
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

URL = re.compile(r"https?://[^\s<>\"'`)\]]+")
HREF = re.compile(r"""href=["'](https?://[^"']+)["']""")
SKIP_HOSTS = ("doc.rust-lang.org",)
# Hosts that return 403 to automated clients for pages that exist.
BLOCKS_SCRIPTS = {
    "https://doi.org/10.1090/": "the AMS blocks scripts (checked by hand)",
}
NO_FRAGMENT_CHECK = ("https://github.com/",)
TEXT_SUFFIXES = {".md", ".json", ".yml", ".yaml", ".sh", ".py", ".toml"}
SKIP_DIRS = {"node_modules", ".git", "dist", "src-static", "static.files"}
AGENT = "baldssl-url-check (+https://github.com/BaDaaS/baldssl)"


def urls_in(path: Path) -> set[str]:
    """The URLs written in one file."""
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return set()
    if path.suffix == ".rs":
        text = "\n".join(
            line.split("//", 1)[1] for line in text.splitlines() if "//" in line
        )
        return {clean(u) for u in URL.findall(text)}
    if path.suffix == ".html":
        return {clean(html.unescape(u)) for u in HREF.findall(text)}
    if path.suffix in TEXT_SUFFIXES or path.name == "Makefile":
        return {clean(u) for u in URL.findall(text)}
    return set()


def clean(url: str) -> str:
    """Drops punctuation that ends a sentence, not the URL."""
    return url.rstrip(".,;:")


def collect(paths: list[str]) -> dict[str, Path]:
    found: dict[str, Path] = {}
    me = Path(__file__).resolve()
    for root in map(Path, paths):
        files = [root] if root.is_file() else sorted(root.rglob("*"))
        for f in files:
            if f.is_dir() or SKIP_DIRS & set(f.parts):
                continue
            if f.resolve() == me:
                continue  # its own allowlist prefixes are not links
            for url in urls_in(f):
                if any(h in url.split("/")[2:3] for h in SKIP_HOSTS):
                    continue
                if "{" in url or "$" in url or "example." in url:
                    continue  # templates and placeholders
                found.setdefault(url, f)
    return found


def fetch(
    url: str, attempts: int = 3
) -> tuple[int | None, bytes | None, str | None]:
    """(status, body or None, error)."""
    if not url.startswith(("https://", "http://")):
        return None, None, "not an http(s) URL"
    for attempt in range(attempts):
        # The scheme is checked above: only http and https reach urlopen.
        request = urllib.request.Request(  # noqa: S310
            url, headers={"User-Agent": AGENT}
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
                kind = response.headers.get("Content-Type", "")
                body = response.read() if "html" in kind else None
                return response.status, body, None
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and attempt + 1 < attempts:
                time.sleep(2**attempt * 3)
                continue
            return e.code, None, None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            if attempt + 1 < attempts:
                time.sleep(2**attempt * 3)
                continue
            return None, None, str(e)
    return None, None, "unreachable"


def check(url: str) -> str | None:
    """None if fine, else the problem."""
    base, _, fragment = url.partition("#")
    status, body, error = fetch(base)
    if error:
        return error
    if status == 403 and any(base.startswith(p) for p in BLOCKS_SCRIPTS):
        return None
    if status is None or status >= 400:
        return f"HTTP {status}"
    if fragment and body is not None and not url.startswith(NO_FRAGMENT_CHECK):
        page = body.decode("utf-8", "replace")
        frag = re.escape(fragment)
        if not re.search(rf"""(id|name)=["']{frag}["']""", page):
            return f"no element #{fragment} on the page"
    return None


def main(paths: list[str]) -> int:
    found = collect(paths)
    print(f"checking {len(found)} URLs")
    failures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = pool.map(lambda u: (u, check(u)), sorted(found))
        for url, problem in results:
            if problem:
                failures.append((url, problem))
                print(f"FAIL {url}: {problem} (in {found[url]})")
    if failures:
        print(f"{len(failures)} unreachable URL(s)")
        return 1
    print("all reachable")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or ["."]))
