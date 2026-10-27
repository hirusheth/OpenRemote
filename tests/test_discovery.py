"""Tests for the firewall-proof discovery fallbacks and helpers."""

import pytest

from atv_remote import discovery
from atv_remote.discovery import TVDevice


def test_subnet_hosts_full_range() -> None:
    hosts = discovery.subnet_hosts("192.168.1.42")
    assert len(hosts) == 254
    assert hosts[0] == "192.168.1.1"
    assert hosts[-1] == "192.168.1.254"
    assert "192.168.1.42" in hosts  # own address is probed too (harmless)
    assert "192.168.1.0" not in hosts and "192.168.1.255" not in hosts


def test_subnet_hosts_requires_ip() -> None:
    assert discovery.subnet_hosts(None) == []


def test_parse_host_port() -> None:
    assert discovery.parse_host_port("192.168.1.50") == ("192.168.1.50", 6467)
    assert discovery.parse_host_port("192.168.1.50:6466") == ("192.168.1.50", 6466)
    with pytest.raises(ValueError):
        discovery.parse_host_port("not an ip")
    with pytest.raises(ValueError):
        discovery.parse_host_port("192.168.1.50:abc")


def test_merge_devices_prefers_named() -> None:
    scanned = [TVDevice(name="TV at 192.168.1.50", host="192.168.1.50", port=6467)]
    mdns = [TVDevice(name="Living Room", host="192.168.1.50", port=6467)]
    merged = discovery.merge_devices(scanned, mdns)
    # First occurrence wins, so order matters: named source should go first.
    named = discovery.merge_devices(mdns, scanned)
    assert named[0].name == "Living Room"
    assert len(merged) == 1 and len(named) == 1


@pytest.mark.asyncio
async def test_find_devices_falls_back_to_scan(monkeypatch) -> None:
    async def empty_mdns(timeout):
        return []

    async def fake_scan(port=6467, timeout=0.25):
        return [TVDevice(name="TV at 10.0.0.7", host="10.0.0.7", port=6467)]

    monkeypatch.setattr(discovery, "discover", empty_mdns)
    monkeypatch.setattr(discovery, "scan_subnet", fake_scan)
    devices, method = await discovery.find_devices(timeout=0.1)
    assert method == "network scan"
    assert devices and devices[0].host == "10.0.0.7"


@pytest.mark.asyncio
async def test_find_devices_prefers_mdns(monkeypatch) -> None:
    async def mdns_devices(timeout):
        return [TVDevice(name="Kitchen TV", host="10.0.0.9", port=6467)]

    async def fail_scan(port=6467, timeout=0.25):  # pragma: no cover
        raise AssertionError("subnet scan must not run when mDNS succeeds")

    monkeypatch.setattr(discovery, "discover", mdns_devices)
    monkeypatch.setattr(discovery, "scan_subnet", fail_scan)
    devices, method = await discovery.find_devices(timeout=0.1)
    assert method == "mDNS" and devices[0].name == "Kitchen TV"


def test_fix_firewall_command_is_wired() -> None:
    from atv_remote import __main__ as cli

    args = cli.build_parser().parse_args(["fix-firewall"])
    assert args.func is cli.cmd_fix_firewall
