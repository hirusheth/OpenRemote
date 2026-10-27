"""Tests for key parsing, the one-shot command wiring and the menu guard."""

import asyncio

import pytest

from atv_remote import __main__ as cli
from atv_remote.keys import parse_keycode


def test_parse_keycode_aliases() -> None:
    assert parse_keycode("power") == 26
    assert parse_keycode("dpad_center") == 23
    assert parse_keycode("volume_up") == 24


def test_parse_keycode_keycode_prefix_and_case() -> None:
    assert parse_keycode("KEYCODE_HOME") == 3
    assert parse_keycode("keycode_search") == 84


def test_parse_keycode_raw_numbers() -> None:
    assert parse_keycode("26") == 26
    assert parse_keycode("0x1a") == 26


def test_parse_keycode_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        parse_keycode("notakey")
    with pytest.raises(ValueError):
        parse_keycode("")


def test_one_shot_commands_are_wired() -> None:
    parser = cli.build_parser()
    args = parser.parse_args(["key", "--host", "1.2.3.4", "power", "--direction", "long"])
    assert args.func is cli.cmd_key
    assert args.key == "power" and args.direction == "long" and args.hold == 0.6
    args = parser.parse_args(["text", "--host", "1.2.3.4", "hello", "world"])
    assert args.func is cli.cmd_text
    assert args.text == ["hello", "world"]
    args = parser.parse_args(["volume", "--host", "1.2.3.4", "up", "--steps", "3"])
    assert args.func is cli.cmd_volume
    assert args.action == "up" and args.steps == 3


def test_key_command_rejects_unknown_key(capsys) -> None:
    """Unknown keys fail at runtime with exit code 2, before any connection."""
    args = cli.build_parser().parse_args(["key", "--host", "1.2.3.4", "notakey"])
    code = asyncio.run(cli.cmd_key(args))
    assert code == 2
    assert "unknown key" in capsys.readouterr().err


def test_menu_store_roundtrip(tmp_path, monkeypatch) -> None:
    from atv_remote import menu
    from atv_remote.discovery import TVDevice

    store = tmp_path / "last_tv.json"
    monkeypatch.setattr(menu, "LAST_TV_FILE", store)
    assert menu.load_last_tv() is None
    device = TVDevice(name="Living Room", host="192.168.1.42", port=6467)
    menu.save_last_tv(device)
    loaded = menu.load_last_tv()
    assert loaded is not None
    assert loaded.host == "192.168.1.42" and loaded.port == 6467
    assert loaded.name == "Living Room"


def test_menu_skips_broken_store(tmp_path, monkeypatch) -> None:
    from atv_remote import menu

    store = tmp_path / "last_tv.json"
    store.write_text("not json", encoding="utf-8")
    monkeypatch.setattr(menu, "LAST_TV_FILE", store)
    assert menu.load_last_tv() is None
