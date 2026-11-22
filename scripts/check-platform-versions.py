#!/usr/bin/env python3
"""Report newer or unavailable CI platforms without changing the matrix.

Docker's official-image metadata identifies maintained tags (Hub also keeps
old tags); its Debian metadata maps released codenames to version numbers.
BSD releases are those supported by the exact VM action commits in CI, not
necessarily the OS vendors' current support lists. Android checks the default
x86_64 emulator images used by CI. Rust's stable and pinned source trees
identify the musl versions bundled with their respective toolchains.
"""

import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent
RAW = "https://raw.githubusercontent.com"
HUB = "https://hub.docker.com/v2/repositories/library/buildpack-deps/tags?page_size=100"
TITLE = "Platform versions to review"
MARKER = "<!-- platform-version-monitor -->"
BSD = ("freebsd", "netbsd", "openbsd", "dragonflybsd")


def fetch(url):
    headers = {"User-Agent": "baldssl-platform-monitor", "Accept": "application/vnd.github+json"}
    with urlopen(Request(url, headers=headers), timeout=60) as response:
        return response.read().decode("utf-8")


def version(value):
    if not re.fullmatch(r"\d+(?:\.\d+)*", value):
        raise ValueError(f"invalid version: {value!r}")
    return tuple(map(int, value.split(".")))


def hub_tags(first_url=HUB):
    url, tags, seen = first_url, set(), set()
    while url:
        if url in seen or urlparse(url).hostname != "hub.docker.com":
            raise ValueError("invalid Docker Hub pagination")
        seen.add(url)
        page = json.loads(fetch(url))
        if not isinstance(page.get("results"), list) or "next" not in page:
            raise ValueError("invalid Docker Hub listing")
        tags.update(item["name"] for item in page["results"])
        url = page["next"]
    if not tags:
        raise ValueError("empty Docker Hub listing")
    return tags


def docker_releases(buildpack, debian, tags):
    # Official image metadata identifies tags still being built, and supplies
    # the distribution and Ubuntu version. Debian's metadata maps codenames.
    debian_versions = dict(re.findall(
        r"(?m)^# ([a-z]+) -- Debian (\d+)(?:\.\d+)? Released\b", debian
    ))
    releases = {}
    for block in buildpack.split("\n\n"):
        directory = re.search(r"(?m)^Directory: (debian|ubuntu)/([a-z]+)$", block)
        names = re.search(r"(?m)^Tags: (.+)$", block)
        if not directory or not names:
            continue
        distro, codename = directory.groups()
        names = names.group(1).split(", ")
        if codename not in names or codename not in tags:
            continue
        if distro == "debian":
            number = debian_versions.get(codename)
            if not number and not ({"testing", "unstable"} & set(names)):
                raise ValueError(f"no released Debian version for {codename}")
        else:
            number = next((name for name in names if re.fullmatch(r"\d+\.\d+", name)), None)
            if not number:
                raise ValueError(f"no Ubuntu version for {codename}")
        if number:
            releases[codename] = (distro, number)
    if not all(any(item[0] == distro for item in releases.values()) for distro in ("debian", "ubuntu")):
        raise ValueError("could not parse maintained Debian and Ubuntu Docker releases")
    return releases


def runner_labels(text):
    section = re.search(r"(?ms)^## Available Images\s*\n(.*?)(?=^## )", text)
    if not section:
        raise ValueError("runner images table missing")
    labels = {}
    for row in section.group(1).splitlines():
        cells = row.split("|")
        if len(cells) < 5 or not re.search(r"\b(?:macOS|Windows|Ubuntu)\b", cells[1], re.I):
            continue
        for label in re.findall(r"`((?:macos|windows|ubuntu)-[0-9][a-z0-9.-]*)`", cells[3]):
            if not re.fullmatch(r"(?:macos-\d+(?:-intel)?|windows-(?:\d+|\d+-arm)|ubuntu-\d+\.\d+(?:-arm)?)", label):
                continue
            labels[label] = bool(re.search(r"deprecated|retired", row, re.I))
    if not all(any(key.startswith(prefix) for key in labels) for prefix in ("macos-", "windows-", "ubuntu-")):
        raise ValueError("could not parse runner labels")
    return labels


def bsd_releases(text):
    table = re.search(r"(?ms)^\| Release \|.*?\n\|[-| :]+\|\s*\n((?:\|.*\n)+)", text)
    if not table:
        raise ValueError("BSD releases table missing")
    releases = set()
    for row in table.group(1).splitlines():
        cells = [cell.strip() for cell in row.strip("|").split("|")]
        if re.fullmatch(r"\d+(?:\.\d+)+", cells[0]) and "✅" in cells[1]:
            releases.add(cells[0])
    if not releases:
        raise ValueError("BSD releases table is empty")
    return releases


def android_releases(text):
    found = {int(n) for n in re.findall(
        r"(?m)^\s*system-images;android-(\d+);default;x86_64\s*\|", text
    )}
    if not found or "Available Packages:" not in text:
        raise ValueError("could not parse Android SDK system images")
    return found


def sdk_listing(sdk):
    result = subprocess.run([str(sdk), "--list"], check=True, capture_output=True, text=True)
    if re.search(r"failed to (?:connect|download|fetch)|(?:io|network) exception", result.stderr, re.I):
        raise ValueError(f"Android SDK listing failed: {result.stderr.strip()}")
    return android_releases(result.stdout)


def musl_version(text):
    match = re.search(r"(?m)^MUSL=musl-(\d+(?:\.\d+)+)\s*$", text)
    if not match:
        raise ValueError("could not parse Rust's musl bundle version")
    return match.group(1)


def compare(manifest, listings):
    """Compare normalized upstream listings with the manifest, deterministically."""
    platforms = {p["id"]: p["versions"] for p in manifest["platforms"]}
    new, retired = [], []
    for distro in ("debian", "ubuntu"):
        tested = [v for v in platforms["glibc"] if v["name"].lower().startswith(distro + " ")]
        if not tested:
            raise ValueError(f"no {distro} versions in manifest")
        newest = max(version(re.search(r"\d+(?:\.\d+)*", v["name"]).group()) for v in tested)
        for tag, (kind, number) in sorted(listings["docker"].items()):
            if kind == distro and version(number) > newest:
                new.append(f"{distro.title()} {number} (`buildpack-deps:{tag}`)")
        for v in tested:
            tag = v["image"].removeprefix("buildpack-deps:")
            if tag not in listings["docker"]:
                retired.append(f"{v['name']} (`{v['image']}` no longer maintained)")

    labels = listings["runners"]
    for family in ("macos", "windows"):
        tested = platforms[family]
        for v in tested:
            if v["runner"] not in labels or labels[v["runner"]]:
                retired.append(f"{v['name']} (`{v['runner']}` unavailable or deprecated)")
        # Compare each architecture separately; Windows ARM and Server are
        # distinct product lines and their numeric versions are not comparable.
        for label, deprecated in sorted(labels.items()):
            if not label.startswith(family + "-") or deprecated:
                continue
            suffix = "-intel" if label.endswith("-intel") else "-arm" if label.endswith("-arm") else ""
            peers = [v["runner"] for v in tested if (
                "-intel" if v["runner"].endswith("-intel") else
                "-arm" if v["runner"].endswith("-arm") else ""
            ) == suffix]
            if peers and int(re.search(r"\d+", label).group()) > max(
                int(re.search(r"\d+", peer).group()) for peer in peers
            ):
                new.append(f"{family.title()} runner `{label}`")
    for v in platforms["musl"]:
        if v["runner"] not in labels or labels[v["runner"]]:
            retired.append(f"musl {v['target']} runner `{v['runner']}` unavailable or deprecated")
        if v["target"] not in listings["rust_targets"]:
            retired.append(f"musl target `{v['target']}` unavailable in pinned Rust")
    if version(listings["musl_latest"]) > version(listings["musl_pinned"]):
        new.append(f"Rust stable bundles musl {listings['musl_latest']} (pinned toolchain: {listings['musl_pinned']})")

    run_apis = {v["run_api"] for v in platforms["android"] if v["mode"] == "run"}
    if not run_apis:
        raise ValueError("no Android runtime APIs in manifest")
    for api in sorted(listings["android"]):
        if api > max(run_apis):
            new.append(f"Android API {api} (default x86_64 system image)")
    for api in sorted(run_apis - listings["android"]):
        retired.append(f"Android API {api} (default x86_64 system image unavailable)")

    for os_name in BSD:
        tested = [v for v in platforms["bsd"] if v["os"] == os_name]
        if not tested:
            raise ValueError(f"no {os_name} versions in manifest")
        available = listings["bsd"][os_name]
        for release in sorted(available, key=version):
            # A prefix such as DragonFly 6.4 selects the newest 6.4.x.
            if any(release == v["release"] or release.startswith(v["release"] + ".") for v in tested):
                continue
            if version(release) > max(version(v["release"]) for v in tested):
                new.append(f"{os_name} {release}")
        for v in tested:
            if not any(r == v["release"] or r.startswith(v["release"] + ".") for r in available):
                retired.append(f"{v['name']} (not supported by pinned VM action)")
    return {"new": new, "retired": retired}


def report(result):
    if not result["new"] and not result["retired"]:
        return ""
    parts = [MARKER, "Review these upstream changes before editing `website/src/platforms.json`.",
             "Unavailable entries may be intentional minimum-version checks; review before dropping them."]
    for key, heading in (("new", "Newer versions"), ("retired", "Unavailable or deprecated")):
        if result[key]:
            parts.extend(["", f"## {heading}", *[f"- {item}" for item in result[key]]])
    return "\n".join(parts) + "\n"


def publish(body, api):
    if not body:
        return
    issues = api("GET", "/issues?state=open&per_page=100", None)
    matches = [issue for issue in issues if "pull_request" not in issue and MARKER in (issue.get("body") or "")]
    if len(matches) > 1:
        raise ValueError("multiple open platform monitor issues")
    if not matches:
        api("POST", "/issues", {"title": TITLE, "body": body})
    elif matches[0]["body"] != body:
        api("PATCH", f"/issues/{matches[0]['number']}", {"body": body})


def main():
    manifest = json.loads((ROOT / "website/src/platforms.json").read_text())
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    pinned = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    if not re.fullmatch(r"\d+\.\d+\.\d+", pinned):
        raise ValueError("Rust toolchain must be a numbered release")
    stable = tomllib.loads(fetch("https://static.rust-lang.org/dist/channel-rust-stable.toml"))
    latest = stable["pkg"]["rust"]["version"].split()[0]
    version(latest)
    pinned_manifest = tomllib.loads(fetch(f"https://static.rust-lang.org/dist/channel-rust-{pinned}.toml"))
    rust_targets = {name for name, info in pinned_manifest["pkg"]["rust-std"]["target"].items() if info["available"]}
    rust_source = lambda release: fetch(f"{RAW}/rust-lang/rust/{release}/src/ci/docker/scripts/musl.sh")
    bsd = {}
    for name in BSD:
        match = re.search(rf"uses:\s*vmactions/{name}-vm@([0-9a-f]{{40}})\b", workflow)
        if not match:
            raise ValueError(f"missing pinned {name} action")
        bsd[name] = bsd_releases(fetch(f"{RAW}/vmactions/{name}-vm/{match.group(1)}/README.md"))
    sdk = Path(os.environ["ANDROID_HOME"]) / "cmdline-tools/latest/bin/sdkmanager"
    listings = {
        "docker": docker_releases(
            fetch(f"{RAW}/docker-library/official-images/master/library/buildpack-deps"),
            fetch(f"{RAW}/docker-library/official-images/master/library/debian"), hub_tags()),
        "runners": runner_labels(fetch(f"{RAW}/actions/runner-images/main/README.md")),
        "bsd": bsd, "android": sdk_listing(sdk), "rust_targets": rust_targets,
        "musl_pinned": musl_version(rust_source(pinned)),
        "musl_latest": musl_version(rust_source(latest)),
    }
    body = report(compare(manifest, listings))
    print(body or "No platform changes found.")
    token = os.environ["GH_TOKEN"]
    repo = os.environ["GITHUB_REPOSITORY"]

    def api(method, path, data):
        # gh follows pagination for issue listing and fails on HTTP errors.
        args = ["gh", "api", "--method", method, f"repos/{repo}{path}"]
        if method == "GET":
            args += ["--paginate", "--slurp"]
        if data is not None:
            args += ["--input", "-"]
        result = subprocess.run(args, input=json.dumps(data) if data is not None else None,
                                capture_output=True, text=True, check=True, env={**os.environ, "GH_TOKEN": token})
        parsed = json.loads(result.stdout)
        return [item for page in parsed for item in page] if method == "GET" else parsed

    publish(body, api)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"platform monitor failed: {error}", file=sys.stderr)
        sys.exit(1)
