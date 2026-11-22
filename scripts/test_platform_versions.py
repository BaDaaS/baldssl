import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch
from subprocess import CompletedProcess

spec = importlib.util.spec_from_file_location(
    "platform_versions", Path(__file__).with_name("check-platform-versions.py")
)
monitor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(monitor)


class PlatformVersionsTest(unittest.TestCase):
    def setUp(self):
        self.manifest = {"platforms": [
            {"id": "glibc", "versions": [
                {"name": "Debian 12 (bookworm)", "image": "buildpack-deps:bookworm"},
                {"name": "Ubuntu 22.04 (jammy)", "image": "buildpack-deps:jammy"},
            ]},
            {"id": "musl", "versions": [
                {"target": "x86_64-unknown-linux-musl", "runner": "ubuntu-24.04"},
            ]},
            {"id": "android", "versions": [
                {"mode": "link-fail", "api": 27},
                {"mode": "run", "api": 28, "run_api": 35},
            ]},
            {"id": "macos", "versions": [{"name": "macOS 15", "runner": "macos-15"}]},
            {"id": "windows", "versions": [{"name": "Windows 2022", "runner": "windows-2022"}]},
            {"id": "bsd", "versions": [
                {"os": name, "name": name + " 6.4", "release": "6.4"}
                for name in monitor.BSD
            ]},
        ]}
        self.listings = {
            "docker": {"bookworm": ("debian", "12"), "jammy": ("ubuntu", "22.04")},
            "runners": {"macos-15": False, "windows-2022": False, "ubuntu-24.04": False},
            "android": {35},
            "bsd": {name: {"6.4.2"} for name in monitor.BSD},
            "rust_targets": {"x86_64-unknown-linux-musl"},
            "musl_pinned": "1.2.5", "musl_latest": "1.2.5",
        }

    def test_exact_changes(self):
        self.listings["docker"].update({"trixie": ("debian", "13"), "noble": ("ubuntu", "24.04")})
        del self.listings["docker"]["jammy"]
        self.listings["runners"].update({"macos-15": True, "macos-26": False, "windows-2025": False})
        self.listings["android"].add(36)
        self.listings["bsd"]["freebsd"].add("7.0")
        self.listings["bsd"]["netbsd"] = {"7.0"}
        self.listings["musl_latest"] = "1.2.6"
        result = monitor.compare(self.manifest, self.listings)
        self.assertEqual(result["new"], [
            "Debian 13 (`buildpack-deps:trixie`)",
            "Ubuntu 24.04 (`buildpack-deps:noble`)",
            "Macos runner `macos-26`", "Windows runner `windows-2025`",
            "Rust stable bundles musl 1.2.6 (pinned toolchain: 1.2.5)",
            "Android API 36 (default x86_64 system image)", "freebsd 7.0", "netbsd 7.0",
        ])
        self.assertEqual(result["retired"], [
            "Ubuntu 22.04 (jammy) (`buildpack-deps:jammy` no longer maintained)",
            "macOS 15 (`macos-15` unavailable or deprecated)",
            "netbsd 6.4 (not supported by pinned VM action)",
        ])

    def test_no_changes_never_calls_api(self):
        body = monitor.report(monitor.compare(self.manifest, self.listings))
        self.assertEqual(body, "")
        monitor.publish(body, lambda *args: self.fail("API must not be called"))

    def test_create_and_update_only_when_changed(self):
        calls = []
        issue = {"number": 123, "body": ""}

        def api(method, path, data):
            calls.append((method, path, data))
            return [issue] if method == "GET" else {}

        body = monitor.report({"new": ["test"], "retired": []})
        monitor.publish(body, api)
        self.assertEqual(calls[-1], ("POST", "/issues", {"title": monitor.TITLE, "body": body}))
        issue["body"] = monitor.MARKER + "\nold"
        monitor.publish(body, api)
        self.assertEqual(calls[-1], ("PATCH", "/issues/123", {"body": body}))
        issue["body"] = body
        calls.clear()
        monitor.publish(body, api)
        self.assertEqual(len(calls), 1)

    def test_upstream_parsers_and_failures(self):
        docker = ("Tags: bookworm, oldstable\nDirectory: debian/bookworm\n\n"
                  "Tags: noble, 24.04\nDirectory: ubuntu/noble\n\n"
                  "Tags: forky, testing\nDirectory: debian/forky\n")
        debian = "# bookworm -- Debian 12.15 Released 11 July 2026\n"
        self.assertEqual(monitor.docker_releases(docker, debian, {"bookworm", "noble", "forky"}),
                         {"bookworm": ("debian", "12"), "noble": ("ubuntu", "24.04")})
        runners = ("## Available Images\n| macOS 15 deprecated | arm64 | `macos-15` | x |\n"
                   "| Windows Server 2022 | x64 | `windows-2022` | x |\n"
                   "| Ubuntu 24.04 | x64 | `ubuntu-24.04` | x |\n## Other\n")
        self.assertTrue(monitor.runner_labels(runners)["macos-15"])
        self.assertEqual(monitor.bsd_releases("| Release | x86_64 |\n|---|---|\n| 6.4.2 | ✅ |\n"),
                         {"6.4.2"})
        self.assertEqual(monitor.android_releases("Available Packages:\n"
                         " system-images;android-36;default;x86_64 | 1 | description\n"), {36})
        self.assertEqual(monitor.musl_version("MUSL=musl-1.2.5\n"), "1.2.5")
        for parser in (monitor.runner_labels, monitor.bsd_releases, monitor.android_releases, monitor.musl_version):
            with self.assertRaises(ValueError):
                parser("upstream error")
        with self.assertRaises(ValueError):
            monitor.docker_releases("", "", set())

    def test_sdkmanager_partial_fetch_failure_is_not_ignored(self):
        output = "Available Packages:\n system-images;android-36;default;x86_64 | 1 | image\n"
        result = CompletedProcess([], 0, stdout=output, stderr="Warning: Failed to download any source lists!")
        with patch.object(monitor.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(ValueError, "Android SDK listing failed"):
                monitor.sdk_listing("sdkmanager")


if __name__ == "__main__":
    unittest.main()
