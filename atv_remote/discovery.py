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
import ipaddress
import socket
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf
from zeroconf.asyncio import AsyncServiceBrowser, AsyncZeroconf

from . import wire
from .certs import ensure_client_cert

SERVICE_TYPE = "_androidtvremote2._tcp.local."

#: The Android TV remote service's TCP port (evidence: passed to the TLS
#: socket in defpackage.asru.b(); mDNS SRV carries the actual value, 6467 is
#: the standard one).
DEFAULT_REMOTE_PORT = 6467


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
    """Collects services from the zeroconf browser (callable handler form)."""

    def __init__(self) -> None:
        self.devices: dict[str, TVDevice] = {}

    def on_service_state_change(
        self, zeroconf: Zeroconf, service_type: str, name: str,
        state_change: Any,
    ) -> None:
        if state_change.name not in ("Added", "Updated"):
            return
        # Resolve asynchronously: the sync get_service_info would block the
        # event loop (and zeroconf forbids it).
        asyncio.ensure_future(self._fetch(zeroconf, service_type, name))

    async def _fetch(self, zeroconf: Zeroconf, service_type: str, name: str) -> None:
        from zeroconf.asyncio import AsyncServiceInfo

        info = AsyncServiceInfo(service_type, name)
        if await info.async_request(zeroconf, 2000):
            device = device_from_service_info(info)
            if device:
                self.devices[name] = device


async def discover(timeout: float = 5.0) -> list[TVDevice]:
    """Browse the local network for Android TV remote services."""
    collector = _Collector()
    azc = AsyncZeroconf()
    try:
        browser = AsyncServiceBrowser(
            azc.zeroconf, [SERVICE_TYPE], handlers=[collector.on_service_state_change]
        )
        await asyncio.sleep(timeout)
        await browser.async_cancel()
    finally:
        await azc.async_close()
    return list(collector.devices.values())


# ---------------------------------------------------------------------------
# outbound-only fallback: scan the local subnet for the remote service port.
# Unlike mDNS this needs no inbound firewall permission on any platform, so it
# keeps discovery working when mDNS is blocked (cancelled firewall popup,
# managed networks, ...).
# ---------------------------------------------------------------------------


def best_local_ipv4() -> str | None:
    """The local IPv4 of the default-route interface (UDP connect trick)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))  # no packet is sent; resolves the route
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def subnet_hosts(local_ip: str | None, prefix: int = 24) -> list[str]:
    """Usable host addresses of the local /24 (network + broadcast excluded)."""
    if not local_ip:
        return []
    network = ipaddress.ip_network(f"{local_ip}/{prefix}", strict=False)
    return [str(host) for host in network.hosts()]


async def _probe(ip: str, port: int, timeout: float) -> str | None:
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout
        )
    except (OSError, asyncio.TimeoutError):
        return None
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, OSError):
        pass
    return ip


async def _describe(device: TVDevice) -> TVDevice:
    """TLS-handshake a found host to read its TV model (best effort).

    The TV announces its own model/vendor in the configure message that opens
    every session (evidence: asrd.f logs "Build information received"; the
    public protocol's RemoteConfigure.device_info carries it). Failures keep
    the generic name."""
    from .pairing import make_ssl_context
    from .certs import DEFAULT_CERT_PATH, DEFAULT_KEY_PATH

    try:
        cert_path, key_path = ensure_client_cert(
            Path(DEFAULT_CERT_PATH).expanduser(), Path(DEFAULT_KEY_PATH).expanduser()
        )
        ctx = make_ssl_context(str(cert_path), str(key_path))
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(device.host, device.port, ssl=ctx), timeout=2.5
        )
        length_bytes = await asyncio.wait_for(reader.readexactly(1), timeout=2.5)
        while length_bytes[0] & 0x80:  # multi-byte varint (never in practice)
            length_bytes += await reader.readexactly(1)
        value = 0
        shift = 0
        for byte in length_bytes:
            value |= (byte & 0x7F) << shift
            shift += 7
        payload = await asyncio.wait_for(reader.readexactly(value), timeout=2.5)
        writer.close()
        configure = wire.parse_inbound(payload).configure()
        if configure and configure.device_info:
            name = " ".join(
                part
                for part in (configure.device_info.vendor, configure.device_info.model)
                if part
            ).strip()
            if name:
                return TVDevice(
                    name=name,
                    host=device.host,
                    port=device.port,
                    properties=device.properties,
                )
    except (OSError, asyncio.TimeoutError, ValueError, ssl.SSLError):
        pass
    return device


async def scan_subnet(
    port: int = DEFAULT_REMOTE_PORT, timeout: float = 0.25
) -> list[TVDevice]:
    """Probe the local /24 for the remote service port (outbound only)."""
    hosts = subnet_hosts(best_local_ipv4())
    found: list[str] = []
    for start in range(0, len(hosts), 96):
        chunk = hosts[start : start + 96]
        results = await asyncio.gather(*[_probe(ip, port, timeout) for ip in chunk])
        found.extend(ip for ip in results if ip)
    devices = [TVDevice(name=f"TV at {ip}", host=ip, port=port) for ip in found]
    if devices:
        described = await asyncio.gather(*[_describe(device) for device in devices])
        return list(described)
    return []


async def find_devices(timeout: float = 5.0) -> tuple[list[TVDevice], str]:
    """mDNS first (fast, named); subnet scan as the firewall-proof fallback.

    Returns (devices, method) where method explains how they were found."""
    mdns_devices = await discover(timeout=timeout)
    if mdns_devices:
        return mdns_devices, "mDNS"
    scanned = await scan_subnet()
    if scanned:
        return scanned, "network scan"
    return [], "none"


def parse_host_port(text: str, default_port: int = DEFAULT_REMOTE_PORT) -> tuple[str, int]:
    """Parse "192.168.1.50" or "192.168.1.50:6466" into (host, port)."""
    text = text.strip()
    if not text:
        raise ValueError("empty address")
    if text.count(":") == 1:
        host_part, port_part = text.split(":", 1)
        try:
            return str(ipaddress.ip_address(host_part.strip())), int(port_part)
        except (ValueError, TypeError) as exc:
            raise ValueError(
                f"{text!r} is not a valid address (expected e.g. 192.168.1.50:6467)"
            ) from exc
    try:
        return str(ipaddress.ip_address(text)), default_port
    except ValueError as exc:
        raise ValueError(f"{text!r} is not a valid IPv4 address") from exc


def merge_devices(*groups: list[TVDevice]) -> list[TVDevice]:
    """Union by host:port, keeping the first (named) occurrence."""
    seen: dict[str, TVDevice] = {}
    for group in groups:
        for device in group:
            key = f"{device.host}:{device.port}"
            seen.setdefault(key, device)
    return list(seen.values())
