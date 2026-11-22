"""Imports at the top of their module, never inside a block."""

from pathlib import Path

from conftest import load

use_at_top = load("use_at_top")


def lines(tmp_path: Path, source: str) -> list[int]:
    path = tmp_path / "lib.rs"
    path.write_text(source, encoding="utf-8")
    return [int(e.split(":")[1]) for e in use_at_top.check(str(path))]


def test_top_level_and_inline_modules_are_fine(tmp_path: Path) -> None:
    source = """use a::b;
pub(crate) use c::d;

mod inner {
    use e::f;
}
"""
    assert lines(tmp_path, source) == []


def test_reports_a_use_inside_a_function(tmp_path: Path) -> None:
    source = """fn f() {
    use a::b;
}

impl S {
    fn g() {
        if x {
            use c::d;
        }
    }
}
"""
    assert lines(tmp_path, source) == [2, 8]


def test_braces_in_literals_and_comments_are_not_blocks(
    tmp_path: Path,
) -> None:
    source = """const A: &str = "{";
const B: char = '{';
// {
use a::b;
"""
    assert lines(tmp_path, source) == []
