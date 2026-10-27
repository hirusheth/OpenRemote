"""A barebones Android TV emulator, for testing OpenRemote without a TV.

Implements the parts of the Android TV Remote v2 protocol a client exercises:

- TLS server on the remote service port (self-signed certificate)
- optional mDNS advertisement as ``_androidtvremote2._tcp.local.``
- the POLO pairing handshake, including generating a valid 6-digit PIN and
  verifying the client's secret (this is the "PIN shown on the TV" - the
  emulator prints it to its console)
- the remote session: configure handshake, capability mask, keep-alive
  pings, power state, volume state, and logging of every key press, text
  input, app link and voice payload the client sends

Client-certificate note: a real TV accepts any client certificate at the TLS
layer, which Python's ``ssl`` server cannot do (an unverifiable certificate
aborts the handshake). The emulator therefore runs without TLS client auth and
reads the OpenRemote client certificate from disk (same PC) or from the
``client_cert_pem`` argument; when it is available the pairing secret is fully
verified, otherwise any secret is accepted and a warning is logged.

Run ``openremote fake-tv`` in one terminal and OpenRemote in another; on the
same PC no firewall configuration is needed (loopback is exempt).
"""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass, field
from pathlib import Path
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from rich.console import Console

from . import wire
from .certs import DEFAULT_CERT_PATH, generate_client_cert
from .keys import KeyCode
from .pairing import (
    STATUS_OK,
    F_CONFIGURATION,
    F_CONFIGURATION_ACK,
    F_OPTIONS,
    F_PAIRING_REQUEST,
    F_PAIRING_REQUEST_ACK,
    F_SECRET,
    F_SECRET_ACK,
    F_STATUS,
    encode_configuration_ack,
    encode_options,
    encode_outer,
    encode_pairing_request_ack,
    encode_secret_ack,
    is_pairing_message,
    make_pairing_pin,
    server_pairing_secret,
)

console = Console()

REMOTE_PORT = 6467
CAPABILITY_MASK = 0x7F  # everything a remote client may want

_KEY_NAMES = {int(value): name.lower() for name, value in KeyCode.__members__.items()}


@dataclass
class FakeTVStats:
    connections: int = 0
    pairings_ok: int = 0
    pairings_failed: int = 0
    keys: dict[str, int] = field(default_factory=dict)
    texts: list[str] = field(default_factory=list)
    voice_bytes: int = 0
    voice_sessions: int = 0
    app_links: list[str] = field(default_factory=list)


class FakeTV:
    """Barebones Android TV emulator. See module docstring."""

    def __init__(
        self,
        name: str = "Fake TV",
        port: int = REMOTE_PORT,
        advertise: bool = True,
        host: str = "0.0.0.0",
        client_cert_pem: bytes | None = None,
    ) -> None:
        self.name = name
        self.port = port
        self.host = host
        self.advertise = advertise
        self.client_cert_pem = client_cert_pem
        self.stats = FakeTVStats()
        self.last_pin: str | None = None
        self._server: asyncio.AbstractServer | None = None
        self._zeroconf = None
        self._service_info = None
        self._cert_pem: bytes = b""
        self._key_pem: bytes = b""

    # ------------------------------------------------------------ lifecycle

    async def start(self) -> None:
        self._cert_pem, self._key_pem = generate_client_cert(self.name)
        if self.client_cert_pem is None and Path(DEFAULT_CERT_PATH).expanduser().exists():
            self.client_cert_pem = Path(DEFAULT_CERT_PATH).expanduser().read_bytes()
        self._client_cert_der: bytes | None = None
        if self.client_cert_pem is not None:
            self._client_cert_der = x509.load_pem_x509_certificate(
                self.client_cert_pem
            ).public_bytes(Encoding.DER)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.verify_mode = ssl.CERT_NONE  # real TVs accept any client cert
        ctx.load_cert_chain(
            certfile=self._pem(self._cert_pem, "faketv-cert"),
            keyfile=self._pem(self._key_pem, "faketv-key"),
        )
        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port, ssl=ctx
        )
        self.port = self._server.sockets[0].getsockname()[1]
        if self.advertise:
            await self._advertise()

    async def stop(self) -> None:
        if self._zeroconf is not None:
            try:
                await self._zeroconf.async_unregister_service(self._service_info)
                await self._zeroconf.async_close()
            except OSError:
                pass
            self._zeroconf = None
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    @staticmethod
    def _pem(data: bytes, stem: str) -> str:
        path = Path(tempfile.gettempdir()) / f"{stem}-{abs(hash(data))}.pem"
        path.write_bytes(data)
        return str(path)

    async def _advertise(self) -> None:
        from zeroconf import ServiceInfo
        from zeroconf.asyncio import AsyncZeroconf

        instance = self.name.replace(" ", "-").replace(".", "-")
        self._service_info = ServiceInfo(
            "_androidtvremote2._tcp.local.",
            f"{instance}._androidtvremote2._tcp.local.",
            port=self.port,
            properties={"isDeviceInStandbyMode": "false", "wp": "1"},
            server=f"{instance}.local.",
        )
        self._zeroconf = AsyncZeroconf()
        try:
            # strict=False: the real service name "_androidtvremote2" is 16
            # bytes, which violates the RFC 6763 15-byte recommendation but is
            # what actual TVs advertise.
            await self._zeroconf.async_register_service(self._service_info, strict=False)
        except Exception as exc:  # noqa: BLE001 - discovery has a scan fallback
            console.print(f"[yellow]mDNS advertisement failed ({exc.__class__.__name__}: "
                          f"{exc}) - continuing without it; the network scan will "
                          f"still find this TV.[/yellow]")
            try:
                await self._zeroconf.async_close()
            except OSError:
                pass
            self._zeroconf = None

    def ensure_client_cert_loaded(self) -> None:
        """Lazily read the OpenRemote client certificate (it may be created
        after this emulator started)."""
        if self._client_cert_der is None:
            path = Path(DEFAULT_CERT_PATH).expanduser()
            if path.exists():
                self.client_cert_pem = path.read_bytes()
                self._client_cert_der = x509.load_pem_x509_certificate(
                    self.client_cert_pem
                ).public_bytes(Encoding.DER)

    # ------------------------------------------------------------- sessions

    async def _handle_client(self, reader: asyncio.StreamReader, writer) -> None:
        self.stats.connections += 1
        peer = writer.get_extra_info("peername")
        console.print(f"[green]connection[/green] from {peer}")
        session = _Session(self, reader, writer)
        try:
            await session.run()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            console.print(f"[dim]disconnected {peer}[/dim]")


class _Session:
    """One TLS connection: either a POLO pairing or a remote session."""

    def __init__(self, tv: FakeTV, reader: asyncio.StreamReader, writer) -> None:
        self.tv = tv
        self.reader = reader
        self.writer = writer
        self.pin: str | None = None
        self._ping_task: asyncio.Task | None = None
        self._voice_bytes = 0

    async def run(self) -> None:
        # The TV announces its capabilities and state as soon as a client
        # connects (evidence: asrd.f expects the configuration at state 2).
        await self._send(self._tv_configure())
        started, volume = self._tv_state()
        await self._send(started)
        await self._send(volume)
        try:
            while True:
                payload = await self._read_message()
                if is_pairing_message(payload):
                    if not await self._handle_pairing(payload):
                        break
                else:
                    if self._ping_task is None:
                        self._ping_task = asyncio.ensure_future(self._ping_loop())
                    self._handle_remote(payload)
        finally:
            if self._ping_task:
                self._ping_task.cancel()

    # ------------------------------------------------------------- pairing

    async def _handle_pairing(self, payload: bytes) -> bool:
        fields = wire.parse_fields(payload)
        status = self._varint(fields, 2, STATUS_OK)
        if status != STATUS_OK:
            return False
        if F_PAIRING_REQUEST in fields:
            client_name = self._string_field(fields[F_PAIRING_REQUEST][1], 2) or "client"
            console.print(f"[cyan]pairing requested by[/cyan] {client_name!r}")
            await self._send(encode_pairing_request_ack(self.tv.name))
        elif F_OPTIONS in fields:
            await self._send(encode_options())
        elif F_CONFIGURATION in fields:
            self.tv.ensure_client_cert_loaded()
            if self.tv._client_cert_der:
                # A valid PIN: check digits derived from both public keys.
                self.pin = make_pairing_pin(self.tv._client_cert_der, self.tv._cert_pem)
            else:  # pragma: no cover - client.pem always exists after first run
                import secrets as _secrets

                self.pin = f"{_secrets.randbelow(0x10000):04x}"
                console.print(
                    "[yellow]client certificate unknown - the PIN check digits "
                    "cannot be validated; any secret will be accepted[/yellow]"
                )
            self.tv.last_pin = self.pin
            console.print(
                f"[bold yellow]PIN shown on the TV screen: {self.pin}[/bold yellow]"
            )
            await self._send(encode_configuration_ack())
        elif F_SECRET in fields:
            secret = self._bytes_field(fields[F_SECRET][1], 1)
            verified = False
            if self.tv._client_cert_der:
                assert self.pin is not None
                expected = server_pairing_secret(
                    self.tv._client_cert_der, self.tv._cert_pem, self.pin
                )
                verified = secret == expected
            else:
                verified = True  # cannot verify without the client certificate
            if verified:
                await self._send(encode_secret_ack())
                self.tv.stats.pairings_ok += 1
                console.print("[green]pairing verified - certificate trusted[/green]")
                return False  # pairing connection ends here
            await self._send(encode_outer(b"", status=402))
            self.tv.stats.pairings_failed += 1
            console.print("[red]pairing secret mismatch[/red]")
            return False
        return True

    # -------------------------------------------------------------- remote

    def _tv_configure(self) -> bytes:
        inner = wire.varint_field(1, CAPABILITY_MASK) + wire.message_field(
            2,
            wire.bytes_field(1, b"FakeTV")
            + wire.bytes_field(2, b"OpenRemote")
            + wire.bytes_field(5, b"com.openremote.faketv"),
        )
        return wire.message_field(1, inner)

    @staticmethod
    def _tv_state() -> bytes:
        """remote_start (on) + current volume, as separate messages."""
        started = wire.message_field(40, wire.varint_field(1, 1))
        volume = wire.message_field(
            50,
            wire.varint_field(6, 15)  # volume_max
            + wire.varint_field(7, 10)  # volume_level
            + wire.varint_field(8, 0),  # volume_muted
        )
        return started, volume

    def _handle_remote(self, payload: bytes) -> None:
        message = wire.parse_inbound(payload)
        if message.oneof == wire.F_CONFIGURE:
            cfg = message.configure()
            if cfg and cfg.device_info:
                console.print(
                    f"[cyan]client configured:[/cyan] {cfg.device_info.vendor} "
                    f"{cfg.device_info.model} (capabilities 0x{cfg.code1:x})"
                )
        elif message.oneof == wire.F_SET_ACTIVE:
            console.print(f"[cyan]client active features[/cyan] "
                          f"0x{message.set_active() or 0:x}")
        elif message.oneof == wire.F_PING_RESPONSE:
            pass
        elif message.oneof == wire.F_KEY_INJECT:
            raw = message.raw(wire.F_KEY_INJECT)
            key_code, direction = 0, 0
            for number, wire_type, value in wire.walk_fields(raw):
                if wire_type == 0:
                    value, _ = wire.decode_varint(value)
                    if number == 1:
                        key_code = value
                    elif number == 2:
                        direction = value
            name = _KEY_NAMES.get(key_code, f"keycode {key_code}")
            self.tv.stats.keys[name] = self.tv.stats.keys.get(name, 0) + 1
            console.print(f"[yellow]key[/yellow] {name} ({key_code}) dir={direction}")
            if key_code == int(KeyCode.SEARCH):
                # Emulate the assistant: begin a voice session.
                self.tv.stats.voice_sessions += 1
                self._voice_bytes = 0
                asyncio.ensure_future(
                    self._send(
                        wire.message_field(
                            wire.F_VOICE_BEGIN,
                            wire.VoiceBegin(
                                session_id=self.tv.stats.voice_sessions,
                                package_name="com.openremote.faketv",
                            ).encode(),
                        )
                    )
                )
        elif message.oneof == wire.F_IME_BATCH_EDIT:
            text = self._decode_ime_text(message.raw(wire.F_IME_BATCH_EDIT))
            self.tv.stats.texts.append(text)
            console.print(f"[cyan]text typed[/cyan] {text!r}")
        elif message.oneof == wire.F_VOICE_BEGIN:
            console.print("[cyan]voice session opened by client[/cyan]")
        elif message.oneof == wire.F_VOICE_PAYLOAD:
            raw = message.raw(wire.F_VOICE_PAYLOAD)
            for number, wire_type, value in wire.walk_fields(raw):
                if number == 2 and wire_type == 2:
                    self._voice_bytes += len(value)
            self.tv.stats.voice_bytes = self._voice_bytes
        elif message.oneof == wire.F_VOICE_END:
            console.print(
                f"[cyan]voice session ended[/cyan] ({self._voice_bytes} bytes PCM)"
            )
        elif message.oneof == wire.F_APP_LINK:
            raw = message.raw(wire.F_APP_LINK)
            for number, wire_type, value in wire.walk_fields(raw):
                if number == 1 and wire_type == 2:
                    link = value.decode("utf-8", "replace")
                    self.tv.stats.app_links.append(link)
                    console.print(f"[cyan]app link[/cyan] {link}")
        elif message.oneof == wire.F_ERROR:
            console.print("[red]client reported an error[/red]")
        else:
            console.print(f"[dim]unhandled oneof {message.oneof}[/dim]")

    # ------------------------------------------------------------- helpers

    async def _ping_loop(self) -> None:
        counter = 0
        while True:
            await asyncio.sleep(5)
            counter += 1
            try:
                await self._send(
                    wire.message_field(
                        wire.F_PING_REQUEST,
                        wire.varint_field(1, counter) + wire.varint_field(2, counter),
                    )
                )
            except (ConnectionError, OSError):
                return

    async def _send(self, payload: bytes) -> None:
        self.writer.write(wire.delimited(payload))
        await self.writer.drain()

    async def _read_message(self) -> bytes:
        length_bytes = bytearray()
        while True:
            byte = await self.reader.readexactly(1)
            length_bytes += byte
            if not (byte[0] & 0x80):
                break
        length, _ = wire.decode_varint(bytes(length_bytes), 0)
        return await self.reader.readexactly(length)

    @staticmethod
    def _varint(fields, number, default):
        entry = fields.get(number)
        if entry is None or entry[0] != 0:
            return default
        value, _ = wire.decode_varint(entry[1])
        return value

    @staticmethod
    def _bytes_field(payload, number):
        for field_number, wire_type, value in wire.walk_fields(payload):
            if field_number == number and wire_type == 2:
                return value
        return b""

    @staticmethod
    def _string_field(payload, number):
        for field_number, wire_type, value in wire.walk_fields(payload):
            if field_number == number and wire_type == 2:
                return value.decode("utf-8", "replace")
        return None

    @staticmethod
    def _decode_ime_text(payload: bytes) -> str:
        # ime_batch_edit: edit_info(3) -> text_field_status(2) -> value(3)
        for number, wire_type, value in wire.walk_fields(payload):
            if number == 3 and wire_type == 2:
                for n2, wt2, v2 in wire.walk_fields(value):
                    if n2 == 2 and wt2 == 2:
                        for n3, wt3, v3 in wire.walk_fields(v2):
                            if n3 == 3 and wt3 == 2:
                                return v3.decode("utf-8", "replace")
        return ""


async def run_fake_tv(name: str, port: int, advertise: bool) -> None:
    tv = FakeTV(name=name, port=port, advertise=advertise)
    await tv.start()
    console.print(
        f"[bold]Fake TV running[/bold] - {name}\n"
        f"  port: {tv.port}\n"
        f"  mDNS: {'advertising as ' + name if advertise else 'disabled'}\n"
        "OpenRemote in another terminal will find and pair with this TV.\n"
        "Press Ctrl+C here to stop."
    )
    try:
        await asyncio.Event().wait()
    finally:
        await tv.stop()
        console.print("[dim]Fake TV stopped.[/dim]")
