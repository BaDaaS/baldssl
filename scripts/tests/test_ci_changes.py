"""The CI job groups a change needs."""

from pathlib import Path

import pytest
from conftest import load

ci_changes = load("ci-changes")


def on(paths: list[str]) -> set[str]:
    """The groups `paths` turn on."""
    return {g for g, v in ci_changes.needed(paths).items() if v}


def test_no_change_needs_nothing() -> None:
    assert on([]) == set()


@pytest.mark.parametrize("path", ci_changes.EVERYTHING)
def test_workflow_makefile_and_rules_need_everything(path: str) -> None:
    assert on([path]) == set(ci_changes.GROUPS)


def test_a_rust_source_needs_the_builds_but_not_lean_or_python() -> None:
    groups = on(["crates/baldssl-x509/src/lib.rs"])
    assert {"rust", "format", "hygiene", "links", "interop"} <= groups
    assert {"website-examples"} <= groups
    assert groups.isdisjoint({"lean", "python", "golden", "os-rng"})


def test_os_rng_follows_the_crypto_crate_only() -> None:
    assert "os-rng" in on(["crates/baldssl-crypto/src/os_rng.rs"])
    assert "os-rng" in on(["website/src/platforms.json"])
    assert "os-rng" not in on(["crates/baldssl-pkey/src/lib.rs"])


def test_an_interop_script_needs_interop_not_the_test_matrix() -> None:
    groups = on(["scripts/pkey-interop.sh"])
    assert "interop" in groups
    assert "rust" not in groups


def test_a_python_script_needs_python() -> None:
    assert "python" in on(["scripts/check_urls.py"])
    assert "python" in on(["scripts/tests/test_check_urls.py"])
    assert "python" not in on(["scripts/interop.sh"])


def test_the_website_alone_needs_only_its_checks() -> None:
    assert on(["website/src/examples.json"]) == {"website-examples", "links"}


def test_the_proofs_need_lean() -> None:
    assert on(["proofs/Baldssl.lean"]) == {"lean"}


def test_the_fixture_pin_needs_the_golden_check_and_the_builds() -> None:
    groups = on(["tests/fixtures.mk"])
    assert {"golden", "rust", "interop"} <= groups


def test_output_lines(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    changed = tmp_path / "changed"
    changed.write_text("proofs/Baldssl.lean\n\n", encoding="utf-8")
    assert ci_changes.main([str(changed)]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert "lean=true" in lines
    assert "rust=false" in lines
    assert len(lines) == len(ci_changes.GROUPS)


def test_all(capsys: pytest.CaptureFixture[str]) -> None:
    assert ci_changes.main(["--all"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out == [f"{g}=true" for g in ci_changes.GROUPS]


def test_usage(capsys: pytest.CaptureFixture[str]) -> None:
    assert ci_changes.main([]) == 2
    assert "Usage" in capsys.readouterr().err
