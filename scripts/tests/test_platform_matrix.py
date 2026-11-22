"""The CI matrices read from the platforms table."""

from conftest import load

platform_matrix = load("platform-matrix")


def test_groups_versions_by_job() -> None:
    data = {
        "platforms": [
            {
                "id": "macos",
                "versions": [{"name": "14", "runner": "m14", "expect": "pass"}],
            },
            {
                "id": "windows",
                "versions": [{"name": "11", "runner": "w11", "expect": "pass"}],
            },
        ]
    }
    out, problems = platform_matrix.matrices(data)
    assert set(out) == {"runners"}
    assert [v["name"] for v in out["runners"]] == ["14", "11"]
    assert problems == []


def test_every_version_states_its_expected_outcome() -> None:
    data = {"platforms": [{"id": "macos", "versions": [{"name": "14"}]}]}
    _, problems = platform_matrix.matrices(data)
    assert any("expect must be one of" in p for p in problems)


def test_reports_unknown_platforms_and_missing_fields() -> None:
    data = {
        "platforms": [
            {"id": "plan9", "versions": []},
            {"id": "glibc", "versions": [{"name": "2.17", "expect": "pass"}]},
        ]
    }
    _, problems = platform_matrix.matrices(data)
    assert any("unknown platform id 'plan9'" in p for p in problems)
    assert any("no ['image']" in p for p in problems)
