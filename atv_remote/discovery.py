"""mDNS discovery of Google TV / Android TV devices.

Evidence (REA, Google Home 4.34.22.2 / classes6.dex):
  - The app browses the mDNS service type ``_androidtvremote2._tcp.local.``
    (string constants used by the hand-rolled mDNS scanner classes
    defpackage.assp/astd/assz with log tags "AtvRemote.MdnsClient" and
    "AtvRemote.MdnsDvcScnner").
  - TXT records on the service include ``isDeviceInStandbyMode`` (read and
    locally updated by defpackage.asry.b/asru.b) and ``wp`` (read at connect).
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field
from typing import Any

from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf
from zeroconf.asyncio import AsyncServiceBrowser, AsyncZeroconf

SERVICE_TYPE = "_androidtvremote2._tcp.local."


@dataclass
class TVDevice:
    """A discovered TV (host/port come from the mDNS SRV record)."""

    name: str
    host: str
    port: int
    properties: dict[str, Any] = field(default_factory=dict)

    @property
    def standby(self) -> bool | None:
        raw = self.properties.get("isDeviceInStandbyMode")
        if raw is None:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", "replace")
        return str(raw).lower() == "true"

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<TVDevice {self.name} {self.host}:{self.port}>"


def device_from_service_info(info: ServiceInfo) -> TVDevice | None:
    addresses = info.parsed_addresses() or []
    if not addresses:
        return None
    props: dict[str, Any] = {}
    for key, value in (info.decoded_properties or {}).items():
        props[key] = value
    host = addresses[0]
    if isinstance(host, (bytes, bytearray)):
        host = socket.inet_ntoa(host)
    return TVDevice(
        name=info.name or info.server or "",
        host=host,
        port=info.port,
        properties=props,
    )


class _Collector:
    def __init__(self) -> None:
        self.devices: dict[str, TVDevice] = {}
        self._zc: Zeroconf | None = None

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        self._update(zc, type_, name)

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        self._update(zc, type_, name)

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        self.devices.pop(name, None)

    def _update(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name, timeout=2000)
        if info is None:
            return
        device = device_from_service_info(info)
        if device:
            self.devices[name] = device


async def discover(timeout: float = 5.0) -> list[TVDevice]:
    """Browse the local network for Android TV remote services."""
    collector = _Collector()
    azc = AsyncZeroconf()
    try:
        browser = AsyncServiceBrowser(azc.zeroconf, [SERVICE_TYPE], handlers=[collector])
        await asyncio.sleep(timeout)
        await browser.async_cancel()
    finally:
        await azc.async_close()
    return list(collector.devices.values())
