"""Trait bounds belong in where clauses."""

from conftest import load

where_clauses = load("where_clauses")


def bounds(source: str) -> list[tuple[str, str]]:
    return [
        (name, bound)
        for _, lt, gt, _ in where_clauses.generic_lists(source)
        for _, name, bound in where_clauses.inline_bounds(source[lt + 1 : gt])
    ]


def test_reports_inline_bounds() -> None:
    assert bounds("fn f<T: Clone + Copy, U>(t: T, u: U) {}") == [
        ("T", "Clone + Copy")
    ]
    assert bounds("impl<T: Debug> S<T> {}") == [("T", "Debug")]


def test_ignores_lifetimes_consts_defaults_and_comments() -> None:
    source = """
fn f<'a, const N: usize, T>(x: &'a [T; N]) where T: Copy {}
struct S<T = u8>(T);
// fn g<T: Clone>() {}
"""
    assert bounds(source) == []


def test_fix_moves_bounds_to_a_where_clause() -> None:
    fixed = where_clauses.fix("fn f<T: Clone>(t: T) -> T {\n    t\n}\n")
    assert bounds(fixed) == []
    assert "fn f<T>(t: T) -> T" in fixed
    assert "where" in fixed
    assert "T: Clone" in fixed


def test_fix_extends_an_existing_where_clause() -> None:
    fixed = where_clauses.fix("fn f<T: Clone, U>(t: T) where U: Copy {}\n")
    assert bounds(fixed) == []
    assert "T: Clone" in fixed
    assert "U: Copy" in fixed
    assert fixed.count("where") == 1
