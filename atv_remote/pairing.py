"""POLO pairing protocol (Android TV Remote v2).

The Google Home app contains no PIN-pairing code: it relies on a client
certificate that was provisioned out-of-band (REA evidence: defpackage.asqa
loads an existing KeyStore; no pairing-protocol strings exist in the APK).
Pairing a *fresh* client certificate happens over the same TLS channel using
Google's "POLO" pairing protocol (AOSP external/google-tv-pairing-protocol),
which rides OuterMessage protobufs with the same varint-delimited framing.

Flow (see AOSP polo.proto and the public protocol documentation):
  client -> OuterMessage{pairing_request{service_name, client_name}}
  TV     -> OuterMessage{pairing_request_ack{server_name}}
  client -> OuterMessage{options{preferred_role: INPUT, encoding: HEX(6)}}
  TV     -> OuterMessage{options{...}}
  client -> OuterMessage{configuration{encoding, client_role: INPUT}}
  TV     -> OuterMessage{configuration_ack}
  ... TV shows a 6-digit hex PIN ...
  client -> OuterMessage{secret{sha256(client_mod || client_exp ||
                                       server_mod || server_exp || pin[2:])}}
  TV     -> OuterMessage{secret_ack}
"""

from __future__ import annotations

import asyncio
import hashlib
import ssl
from dataclasses import dataclass

from . import wire
from .certs import public_numbers

# OuterMessage field numbers (polo.proto)
F_PROTOCOL_VERSION = 1
F_STATUS = 2
F_PAIRING_REQUEST = 10
F_PAIRING_REQUEST_ACK = 11
F_OPTIONS = 20
F_CONFIGURATION = 30
F_CONFIGURATION_ACK = 31
F_SECRET = 40
F_SECRET_ACK = 41

STATUS_OK = 200
SERVICE_NAME = "atvremote"


@dataclass
class _PairingState:
    started: asyncio.Future[bool]
    finished: asyncio.Future[bool]


def _outer(fields: bytes, status: int = STATUS_OK) -> bytes:
    return wire.varint_field(F_PROTOCOL_VERSION, 2) + wire.varint_field(F_STATUS, status) + fields


def encode_pairing_request(client_name: str) -> bytes:
    inner = (
        wire.bytes_field(1, SERVICE_NAME.encode())
        + wire.bytes_field(2, client_name.encode())
    )
    return _outer(wire.message_field(F_PAIRING_REQUEST, inner))


def encode_options() -> bytes:
    # Options{input_encodings[0]{type: HEX(3), symbol_length: 6}, preferred_role: INPUT(1)}
    encoding = wire.varint_field(1, 3) + wire.varint_field(2, 6)
    options = (
        wire.message_field(1, encoding)  # repeated input_encodings
        + wire.varint_field(3, 1)  # preferred_role = ROLE_TYPE_INPUT
    )
    return _outer(wire.message_field(F_OPTIONS, options))


def encode_configuration() -> bytes:
    # Configuration{encoding{type: HEX(3), symbol_length: 6}, client_role: INPUT(1)}
    encoding = wire.varint_field(1, 3) + wire.varint_field(2, 6)
    configuration = wire.message_field(1, encoding) + wire.varint_field(2, 1)
    return _outer(wire.message_field(F_CONFIGURATION, configuration))


def encode_secret(secret: bytes) -> bytes:
    return _outer(wire.message_field(F_SECRET, wire.bytes_field(1, secret)))


def pairing_secret(
    client_cert_pem: bytes,
    server_cert_der: bytes,
    pin: str,
) -> bytes:
    """Compute the pairing secret from both certificates and the TV's PIN.

    The PIN is 6 hex digits: ``pp hhhhhh`` where ``pp`` must equal the first
    byte of sha256(client_mod || client_exp || server_mod || server_exp ||
    pin[2:]).
    """
    from cryptography import x509

    client_mod, client_exp = public_numbers(client_cert_pem)
    server = x509.load_der_x509_certificate(server_cert_der)
    numbers = server.public_key().public_numbers()  # type: ignore[union-attr]
    server_mod, server_exp = numbers.n, numbers.e

    h = hashlib.sha256()
    h.update(bytes.fromhex(f"{client_mod:X}"))
    h.update(bytes.fromhex(f"0{client_exp:X}"))
    h.update(bytes.fromhex(f"{server_mod:X}"))
    h.update(bytes.fromhex(f"0{server_exp:X}"))
    h.update(bytes.fromhex(pin[2:]))
    digest = h.digest()
    if digest[0] != int(pin[0:2], 16):
        raise ValueError("pairing PIN does not match the expected hash")
    return digest


class PairingClient:
    """Runs the POLO pairing handshake over an open TLS stream reader/writer."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        client_name: str,
        client_cert_pem: bytes,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._client_name = client_name
        self._client_cert_pem = client_cert_pem
        self._started: asyncio.Future[bool] | None = None
        self._finished: asyncio.Future[bool] | None = None

    async def _send(self, message: bytes) -> None:
        self._writer.write(wire.delimited(message))
        await self._writer.drain()

    async def _read_message(self, timeout: float = 10.0) -> dict[int, tuple[int, bytes]]:
        length_bytes = await asyncio.wait_for(self._read_varint(), timeout)
        length, _ = wire.decode_varint(length_bytes, 0)
        payload = await asyncio.wait_for(self._reader.readexactly(length), timeout)
        return wire.parse_fields(payload)

    async def _read_varint(self) -> bytes:
        buf = bytearray()
        while True:
            byte = await self._reader.readexactly(1)
            buf += byte
            if not (byte[0] & 0x80):
                return bytes(buf)
            if len(buf) >= 10:
                raise ValueError("varint too long")

    async def start(self) -> None:
        """Send pairing_request and complete the negotiation up to the PIN."""
        await self._send(encode_pairing_request(self._client_name))
        while True:
            fields = await self._read_message()
            status = self._varint(fields, F_STATUS, STATUS_OK)
            if status != STATUS_OK:
                raise RuntimeError(f"pairing failed with status {status}")
            if F_PAIRING_REQUEST_ACK in fields:
                await self._send(encode_options())
            elif F_OPTIONS in fields:
                await self._send(encode_configuration())
            elif F_CONFIGURATION_ACK in fields:
                return  # TV is now showing the PIN

    async def finish(self, pin: str) -> None:
        """Send the secret computed from the PIN shown on the TV."""
        if not pin or len(pin) != 6:
            raise ValueError("PIN must be exactly 6 hex digits")
        try:
            int(pin, 16)
        except ValueError as exc:
            raise ValueError("PIN must be hex") from exc
        server_cert = self._writer.get_extra_info("ssl_object").getpeercert(True)
        if not server_cert:
            raise RuntimeError("no server certificate available")
        secret = pairing_secret(self._client_cert_pem, bytes(server_cert), pin)
        await self._send(encode_secret(secret))
        fields = await self._read_message()
        if F_SECRET_ACK not in fields:
            raise RuntimeError("pairing was not acknowledged by the TV")

    @staticmethod
    def _varint(fields: dict[int, tuple[int, bytes]], number: int, default: int) -> int:
        entry = fields.get(number)
        if entry is None or entry[0] != 0:
            return default
        value, _ = wire.decode_varint(entry[1])
        return value


def make_ssl_context(cert_path: str, key_path: str, verify: bool = False) -> ssl.SSLContext:
    """TLS client context with our client certificate.

    The TV presents a self-signed certificate; like the Google Home app
    (which performs no CA verification of the TV), verification is off by
    default."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED if verify else ssl.CERT_NONE
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx
