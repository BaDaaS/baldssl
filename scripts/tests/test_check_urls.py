"""Finding the URLs to check, without the network."""

from pathlib import Path

from conftest import load

check_urls = load("check_urls")


def test_clean_drops_trailing_punctuation() -> None:
    assert (
        check_urls.clean("https://www.example.com/x.")
        == "https://www.example.com/x"
    )
    assert (
        check_urls.clean("https://www.example.com/x),")
        == "https://www.example.com/x)"
    )


def test_rust_urls_come_from_comments_only(tmp_path: Path) -> None:
    path = tmp_path / "lib.rs"
    path.write_text(
        "//! See <https://www.rfc-editor.org/rfc/rfc5280>.\n"
        'const S: &str = "https://www.example.com/not-a-comment";\n',
        encoding="utf-8",
    )
    assert check_urls.urls_in(path) == {
        "https://www.rfc-editor.org/rfc/rfc5280"
    }


def test_only_http_urls_are_fetched() -> None:
    assert check_urls.fetch("file:///etc/passwd")[2] == "not an http(s) URL"
