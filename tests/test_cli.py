"""CLI behavior tests: self-explanatory invocation, help, wizard wiring."""

import io
from contextlib import redirect_stdout

import pytest

from atv_remote import __main__ as cli


def test_bare_invocation_prints_guide() -> None:
    """Running with no arguments must print the getting-started guide."""
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = cli.main([])
    out = buffer.getvalue()
    assert code == 0
    for token in ("discover", "pair", "remote", "wizard", "--help", "<tv-ip>"):
        assert token in out, f"guide is missing '{token}'"


def test_version_flag(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--version"])
    assert excinfo.value.code == 0
    assert "openremote 0." in capsys.readouterr().out


def test_top_level_help_shows_examples(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--help"])
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert "examples:" in out
    assert "openremote wizard" in out
    assert "--host" in out


def test_subcommand_help_is_informative(capsys) -> None:
    with pytest.raises(SystemExit):
        cli.main(["pair", "--help"])
    out = capsys.readouterr().out
    assert "PIN" in out  # explains what pairing does


def test_parser_wires_all_commands() -> None:
    parser = cli.build_parser()
    args = parser.parse_args(["discover", "--timeout", "2"])
    assert args.func is cli.cmd_discover
    assert args.timeout == 2.0
    for command, func in (
        ("pair", cli.cmd_pair),
        ("remote", cli.cmd_remote),
        ("wizard", cli.cmd_wizard),
    ):
        args = parser.parse_args([command])
        assert args.func is func
