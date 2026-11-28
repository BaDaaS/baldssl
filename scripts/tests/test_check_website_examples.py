"""The display rules of the website's examples, and the install commands
they run."""

from conftest import load

examples = load("check_website_examples")


def test_a_command_within_the_width_passes() -> None:
    assert examples.displayed(["openssl version"]) == []
    assert examples.displayed(["openssl req -new \\", "  -subj /CN=x"]) == []


def test_a_line_over_the_width_is_reported() -> None:
    line = "x" * (examples.MAX_WIDTH + 1)
    assert examples.displayed([line]) == [
        f"line 1 is {examples.MAX_WIDTH + 1} characters"
    ]
    assert examples.displayed(["x" * examples.MAX_WIDTH]) == []


def test_a_missing_continuation_is_reported() -> None:
    assert examples.displayed(["openssl req", "  -new"]) == [
        "line 1: continuation backslash"
    ]


def test_a_trailing_continuation_is_reported() -> None:
    assert examples.displayed(["openssl req \\"]) == [
        "line 1: continuation backslash"
    ]
    assert examples.displayed(["openssl req \\", "  -new \\"]) == [
        "line 2: continuation backslash"
    ]


def test_the_baldssl_variant_replaces_the_program_only() -> None:
    assert (
        examples.baldssl_variant("openssl x509 -in openssl.pem")
        == "baldssl x509 -in openssl.pem"
    )
    assert (
        examples.baldssl_variant("cat a | openssl pkey")
        == "cat a | baldssl pkey"
    )


def test_install_commands_build_this_checkout() -> None:
    shown = "cargo install --git https://github.com/BaDaaS/baldssl baldssl"
    local = examples.local_install(shown)
    assert local == f"cargo install --git {examples.ROOT.as_uri()} baldssl"
    assert examples.local_install("baldssl version") == "baldssl version"
