"""The `_opt` convention: a function returning an Option is named `_opt`."""

from pathlib import Path

from conftest import load

opt_suffix = load("opt_suffix")


def offenders(tmp_path: Path, source: str) -> list[str]:
    path = tmp_path / "lib.rs"
    path.write_text(source, encoding="utf-8")
    return [e.split("`")[1] for e in opt_suffix.check(str(path))]


def test_reports_an_option_without_the_suffix(tmp_path: Path) -> None:
    assert offenders(tmp_path, "pub fn decode(b: &[u8]) -> Option<u8> {}") == [
        "decode"
    ]


def test_reports_generic_functions_and_methods(tmp_path: Path) -> None:
    source = """
impl Foo {
    fn first<T>(xs: &[T]) -> Option<&T> where T: Copy { None }
    pub(crate) fn get(&self) -> Option<u8> { None }
}
"""
    assert offenders(tmp_path, source) == ["first", "get"]


def test_accepts_the_suffix_results_and_trait_methods(tmp_path: Path) -> None:
    source = """
fn decode_opt(b: &[u8]) -> Option<u8> { None }
fn decode(b: &[u8]) -> Result<u8, E> { todo!() }
fn nested(b: &[u8]) -> Result<Option<u8>, E> { todo!() }
fn next(&mut self) -> Option<u8> { None }
fn partial_cmp(&self, o: &Self) -> Option<Ordering> { None }
"""
    assert offenders(tmp_path, source) == []


def test_an_option_in_a_parameter_is_not_the_return_type(
    tmp_path: Path,
) -> None:
    source = "fn new(f: fn(u8) -> Option<u8>, g: Option<u8>) -> Self {}"
    assert offenders(tmp_path, source) == []
