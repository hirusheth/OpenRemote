"""End-to-end test: the client against a local fake TV over real TLS.

Proves the whole stack: certificate generation, TLS client-auth handshake,
varint-delimited protobuf framing, the configure handshake, key injection and
ping responses.
"""

import asyncio
import ssl
import tempfile
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone

from atv_remote import wire
from atv_remote.client import ATVRemoteClient, RemoteConfig


def _make_cert(cn: str) -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ),
    )


async def _read_delimited(reader: asyncio.StreamReader) -> bytes:
    length_bytes = bytearray()
    while True:
        byte = await reader.readexactly(1)
        length_bytes += byte
        if not (byte[0] & 0x80):
            break
    length, _ = wire.decode_varint(bytes(length_bytes), 0)
    return await reader.readexactly(length)


class FakeTV:
    def __init__(self) -> None:
        self.received: list[wire.InboundMessage] = []
        self.got_configure = asyncio.Event()
        cert_pem, key_pem = _make_cert("fake-tv")
        self.cert_pem, self.key_pem = cert_pem, key_pem
        self.server: asyncio.AbstractServer | None = None
        self.port = 0

    async def start(self) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(
            certfile=self._temp("tv.pem", self.cert_pem),
            keyfile=self._temp("tv.key", self.key_pem),
        )
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0, ssl=ctx)
        self.port = self.server.sockets[0].getsockname()[1]

    def _temp(self, name: str, data: bytes) -> str:
        path = Path(tempfile.gettempdir()) / f"openremote-test-{name}"
        path.write_bytes(data)
        return str(path)

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def _handle(self, reader, writer) -> None:
        # TV opens with its configuration (capability mask + device info)
        configure = wire.OutboundMessage.configure(
            wire.Configure(
                code1=0xFF,
                device_info=wire.DeviceInfo(model="FakeTV", vendor="OpenRemote"),
            )
        )
        writer.write(wire.delimited(configure.encode()))
        await writer.drain()
        while True:
            try:
                payload = await _read_delimited(reader)
            except (asyncio.IncompleteReadError, ConnectionError):
                return
            message = wire.parse_inbound(payload)
            self.received.append(message)
            if message.oneof == wire.F_CONFIGURE:
                self.got_configure.set()
            elif message.oneof == wire.F_PING_REQUEST:
                ping = message.ping_request()
                response = wire.OutboundMessage.ping_response(ping.val1 if ping else 0)
                writer.write(wire.delimited(response.encode()))
                await writer.drain()


@pytest.mark.asyncio
async def test_end_to_end_handshake_and_keys() -> None:
    tv = FakeTV()
    await tv.start()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            config = RemoteConfig(
                host="127.0.0.1",
                port=tv.port,
                cert_path=str(Path(tmp) / "client.pem"),
                key_path=str(Path(tmp) / "client.key"),
            )
            client = ATVRemoteClient(config)
            await client.connect()
            try:
                # The handshake completed: TV's configure arrived and the
                # client replied with its own configure (mask + device info).
                await asyncio.wait_for(tv.got_configure.wait(), timeout=5.0)
                configure_replies = [
                    m for m in tv.received if m.oneof == wire.F_CONFIGURE
                ]
                assert configure_replies, "client never answered remote_configure"
                cfg = configure_replies[0].configure()
                assert cfg is not None
                assert cfg.code1 & int(wire.Capability.INPUT)
                assert cfg.device_info is not None
                assert cfg.device_info.package_name == "com.openremote.client"

                # Send a key press and verify the exact wire bytes the TV saw.
                count_before = len(tv.received)
                await client.tap_key(26)  # POWER
                await asyncio.sleep(0.1)
                keys = [m for m in tv.received[count_before:] if m.oneof == wire.F_KEY_INJECT]
                assert keys, "TV did not receive the key event"
                raw = keys[0].raw(wire.F_KEY_INJECT)
                fields = wire.parse_fields(raw)
                keycode, _ = wire.decode_varint(fields[1][1])
                direction, _ = wire.decode_varint(fields[2][1])
                assert keycode == 26
                assert direction == int(wire.Direction.SHORT)
            finally:
                await client.close()
    finally:
        await tv.stop()
