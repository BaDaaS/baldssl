"""The README and the website list the same practices."""

from pathlib import Path

from conftest import load

check_practices = load("check_practices")


def test_titles_of_the_practices_section(tmp_path: Path) -> None:
    readme = tmp_path / "README.md"
    readme.write_text(
        "## Building\n\n- **Not a practice.** Text.\n\n"
        "## Engineering practices\n\nIntro.\n\n"
        "- **First one.** Text.\n  More text.\n"
        "- **Second, with a comma.** Text.\n\n"
        "## License\n\n- **Not one either.** Text.\n",
        encoding="utf-8",
    )
    assert check_practices.readme_titles(str(readme)) == [
        "First one",
        "Second, with a comma",
    ]


def test_no_section_means_no_titles(tmp_path: Path) -> None:
    readme = tmp_path / "README.md"
    readme.write_text("## Building\n\n- **A.** B.\n", encoding="utf-8")
    assert check_practices.readme_titles(str(readme)) == []
