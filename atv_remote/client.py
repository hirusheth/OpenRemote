"""Async client for the Android TV Remote v2 protocol.

Transport (APK evidence, REA):
  - TLS SSLSocket with a client certificate (defpackage.asru.b() builds the
    socket from KeyManagers loaded by defpackage.asqa); keepAlive + tcpNoDelay;
    the TV's own certificate is self-signed and not CA-verified.
  - Framing: varint-length-delimited protobuf messages in both directions
    (asrs.handleMessage -> writeDelimitedTo; asru.b -> parseDelimitedFrom).

Protocol:
  - On connect the TV sends RemoteMessage.remote_configure{code1: capability
    mask, device_info}; the client replies with its own capability mask and
    device info (APK evidence: asrd.f state machine; public protocol agrees).
  - The TV pings every ~5s (remote_ping_request) and the client must answer
    (remote_ping_response) or the connection is dropped.
  - Keys go out as RemoteMessage.remote_key_inject{key_code, direction}
    (APK class asvg at envelope field 10).
  - remote_start (field 40) reports the TV power state (APK class asvk).
  - Voice: send KEYCODE_SEARCH, wait for remote_voice_begin{session_id}, echo
    it, stream remote_voice_payload{session_id, samples} (16-bit PCM 8kHz
    mono) and close with remote_voice_end.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from . import wire
from .certs import ensure_client_cert
from .keys import KeyCode
from .pairing import make_ssl_context
from .wire import Capability, Configure, DeviceInfo, Direction, KeyInject

VOICE_CHUNK_SIZE = 20 * 1024
VOICE_CHUNK_MIN_SIZE = 8 * 1024
IDLE_TIMEOUT = 16.0  # public protocol: server pings every 5s, drops after 3


@dataclass
class TVState:
    is_on: bool | None = None
    current_app: str | None = None
    volume: dict | None = None
    device_info: DeviceInfo | None = None
    supported_capabilities: int = 0
    ime_counter: int = 0
    ime_field_counter: int = 0


@dataclass
class RemoteConfig:
    host: str
    port: int
    client_name: str = "OpenRemote"
    cert_path: str = "~/.config/openremote/client.pem"
    key_path: str = "~/.config/openremote/key.pem"
    enable_ime: bool = True
    enable_voice: bool = True

    @staticmethod
    def default_capability_mask() -> int:
        """Features this client claims in remote_configure (asub bit values)."""
        return (
            Capability.INPUT
            | Capability.IME
            | Capability.VOICE
            | Capability.POWER
            | Capability.VOLUME
        )


Callback = Callable[[TVState], Awaitable[None] | None]


class ATVRemoteClient:
    """Speaks the Android TV Remote v2 protocol to one TV."""

    def __init__(
        self,
        config: RemoteConfig,
        on_update: Callback | None = None,
        on_disconnect: Callable[[Exception | None], None] | None = None,
    ) -> None:
        self.config = config
        self.state = TVState()
        self._on_update = on_update
        self._on_disconnect = on_disconnect
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._reader_task: asyncio.Task | None = None
        self._idle_timer: asyncio.TimerHandle | None = None
        self._send_lock = asyncio.Lock()
        self._closed = False
        self._configured = asyncio.Event()
        self._voice_session: int | None = None
        self._voice_begin_waiter: asyncio.Future[int] | None = None

    # ------------------------------------------------------------- lifecycle

    async def connect(self, verify_server: bool = False) -> None:
        """Open the TLS channel and wait for the initial configuration."""
        import pathlib

        cert_path, key_path = ensure_client_cert(
            pathlib.Path(self.config.cert_path).expanduser(),
            pathlib.Path(self.config.key_path).expanduser(),
        )
        ctx = make_ssl_context(str(cert_path), str(key_path), verify=verify_server)
        self._reader, self._writer = await asyncio.open_connection(
            self.config.host, self.config.port, ssl=ctx
        )
        self._reader_task = asyncio.create_task(
            self._read_loop(), name="openremote-reader"
        )
        await asyncio.wait_for(self._configured.wait(), timeout=10.0)

    async def close(self) -> None:
        self._closed = True
        if self._reader_task:
            self._reader_task.cancel()
            self._reader_task = None
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            self._writer = None
            self._reader = None

    # ------------------------------------------------------------------ keys

    async def send_key(self, key_code: int | KeyCode, direction: Direction = Direction.SHORT) -> None:
        await self._send(
            wire.OutboundMessage.key_inject(
                KeyInject(key_code=int(key_code), direction=Direction(direction))
            )
        )

    async def tap_key(self, key_code: int | KeyCode, hold: float = 0.05) -> None:
        await self.send_key(key_code, Direction.SHORT)
        await asyncio.sleep(hold)

    async def send_text(self, text: str) -> None:
        """Type text into the focused field on the TV (IME)."""
        if not text:
            raise ValueError("text cannot be empty")
        await self._send(
            wire.OutboundMessage.ime_batch_edit(
                wire.ImeBatchEdit(
                    ime_counter=self.state.ime_counter,
                    field_counter=self.state.ime_field_counter,
                    text=text,
                )
            )
        )

    async def launch_app(self, app_link: str) -> None:
        await self._send(wire.OutboundMessage.app_link(wire.AppLinkLaunch(app_link)))

    # ----------------------------------------------------------------- voice

    async def start_voice(self, timeout: float = 2.0) -> int:
        """Trigger the assistant (KEYCODE_SEARCH) and open a voice session."""
        if self._voice_session is not None:
            raise RuntimeError("voice session already in progress")
        loop = asyncio.get_running_loop()
        self._voice_begin_waiter = loop.create_future()
        await self.send_key(KeyCode.SEARCH)
        session_id = await asyncio.wait_for(self._wait_voice_begin(), timeout)
        self._voice_session = session_id
        # Echo the begin message back, as the protocol requires.
        await self._send(
            wire.OutboundMessage.voice_begin(wire.VoiceBegin(session_id=session_id))
        )
        return session_id

    async def _wait_voice_begin(self) -> int:
        assert self._voice_begin_waiter is not None
        try:
            return await self._voice_begin_waiter
        finally:
            self._voice_begin_waiter = None

    async def send_voice_chunk(self, samples: bytes, session_id: int | None = None) -> None:
        session = session_id if session_id is not None else self._voice_session
        if session is None:
            raise RuntimeError("no voice session")
        for i in range(0, len(samples), VOICE_CHUNK_SIZE):
            chunk = samples[i : i + VOICE_CHUNK_SIZE]
            if len(chunk) < VOICE_CHUNK_MIN_SIZE:
                chunk = chunk.ljust(VOICE_CHUNK_MIN_SIZE, b"\x00")
            await self._send(
                wire.OutboundMessage.voice_payload(
                    wire.VoicePayload(session_id=session, samples=chunk)
                )
            )

    async def end_voice(self) -> None:
        if self._voice_session is None:
            return
        session = self._voice_session
        self._voice_session = None
        await self._send(wire.OutboundMessage.voice_end(wire.VoiceEnd(session_id=session)))

    # -------------------------------------------------------------- internal

    async def _send(self, message: wire.OutboundMessage) -> None:
        if self._writer is None:
            raise ConnectionError("not connected")
        self._reset_idle_timer()
        payload = wire.delimited(message.encode())
        async with self._send_lock:
            self._writer.write(payload)
            await self._writer.drain()

    def _reset_idle_timer(self) -> None:
        loop = asyncio.get_event_loop()
        if self._idle_timer:
            self._idle_timer.cancel()
        self._idle_timer = loop.call_later(IDLE_TIMEOUT, self._idle_close)

    def _idle_close(self) -> None:
        if self._writer and not self._writer.is_closing():
            self._writer.close()

    async def _read_loop(self) -> None:
        assert self._reader is not None
        try:
            while not self._closed:
                length_bytes = await self._read_varint()
                length, _ = wire.decode_varint(length_bytes, 0)
                payload = await self._reader.readexactly(length)
                self._reset_idle_timer()
                message = wire.parse_inbound(payload)
                self._handle(message)
        except asyncio.CancelledError:
            pass
        except (asyncio.IncompleteReadError, ConnectionError, OSError, ValueError) as exc:
            if not self._closed:
                if self._on_disconnect:
                    self._on_disconnect(exc)
                elif not self._writer.is_closing():
                    pass

    async def _read_varint(self) -> bytes:
        assert self._reader is not None
        buf = bytearray()
        while True:
            byte = await self._reader.readexactly(1)
            buf += byte
            if not (byte[0] & 0x80):
                return bytes(buf)
            if len(buf) >= 10:
                raise ValueError("varint too long")

    def _handle(self, message: wire.InboundMessage) -> None:
        changed = False
        if configure := message.configure():
            self.state.supported_capabilities = configure.code1
            if configure.device_info:
                self.state.device_info = configure.device_info
            mask = RemoteConfig.default_capability_mask() & configure.code1
            if self.config.enable_ime:
                mask |= Capability.IME
            if self.config.enable_voice:
                mask |= Capability.VOICE
            asyncio.ensure_future(self._reply_configure(mask))
            changed = True
        elif (active := message.set_active()) is not None:
            asyncio.ensure_future(
                self._send(wire.OutboundMessage.set_active(active))
            )
        elif message.oneof == wire.F_PING_REQUEST:
            ping = message.ping_request()
            if ping:
                asyncio.ensure_future(
                    self._send(wire.OutboundMessage.ping_response(ping.val1))
                )
        elif (started := message.started()) is not None:
            self.state.is_on = started
            changed = True
        elif (session := message.voice_session_id()) is not None:
            if self._voice_begin_waiter and not self._voice_begin_waiter.done():
                self._voice_begin_waiter.set_result(session)
        elif (counters := message.ime_counters()) is not None:
            self.state.ime_counter, self.state.ime_field_counter = counters
        elif (app := message.current_app()) is not None:
            self.state.current_app = app
            changed = True
        elif (volume := message.volume()) is not None:
            self.state.volume = volume
            changed = True
        elif message.oneof == wire.F_ERROR:
            pass  # remote_error: logged upstream if needed
        if message.oneof == wire.F_CONFIGURE:
            self._configured.set()
        if changed and self._on_update:
            result = self._on_update(self.state)
            if asyncio.iscoroutine(result):
                asyncio.ensure_future(result)

    async def _reply_configure(self, mask: int) -> None:
        info = DeviceInfo(
            model=self.config.client_name,
            vendor="OpenRemote",
            package_name="com.openremote.client",
            app_version="0.1.0",
        )
        await self._send(wire.OutboundMessage.configure(Configure(code1=mask, device_info=info)))
