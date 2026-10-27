"""Protobuf wire codec for the Android TV Remote v2 protocol (hand-rolled).

No protoc/gencode needed: only the handful of messages this remote uses are
encoded/decoded by hand, byte-compatible with the protocol's protobuf schema.
Everything the client doesn't understand is preserved as raw unknown fields.

Schema sources (see EVIDENCE.md):
  - APK evidence (REA/JADX decompilation of Google Home 4.34.22.2): the app's
    envelope has a single oneof; key events ride field 10 with
    ``key_code = 1`` (Android KeyEvent code) and ``direction = 2`` (enum).
  - Public protocol cross-check (Apache-2.0 ``androidtvremote2`` /
    ``remotemessage.proto``), which names the same wire fields:
    ``RemoteMessage.remote_key_inject = 10 (RemoteKeyInject)`` with
    ``RemoteDirection`` {UNKNOWN=0, START_LONG=1, END_LONG=2, SHORT=3},
    ``remote_configure = 1``, ``remote_set_active = 2``,
    ``remote_ping_request/response = 8/9``, ``remote_voice_begin/payload/end =
    30/31/32``, ``remote_start = 40``, volume = 50/51, ``remote_error = 3``,
    IME = 20/21/22, app link = 90.

Socket framing (APK evidence: asrs.handleMessage / asru.b): every message is
``varint(byte_length) || message_bytes`` — protobuf "delimited" format.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Iterator


class Direction(IntEnum):
    """RemoteDirection enum (wire values)."""

    UNKNOWN = 0
    START_LONG = 1
    END_LONG = 2
    SHORT = 3


class Capability(IntEnum):
    """Capability/feature bits.

    APK evidence (REA ev_2ecec7ed, defpackage.asub <clinit>): INPUT=0x2,
    IME=0x4, VOICE=0x8, PTT_ASSISTANT=0x10, POWER=0x20, VOLUME=0x40,
    GAMEPAD=0x100, AUDIO_DEVICES=0x200, FIND_MY_REMOTE=0x400, APP_LINK=0x800.
    The low bits agree with the public protocol's feature flags (KEY=2, IME=4,
    VOICE=8, POWER=32, VOLUME=64).
    """

    INPUT = 0x2
    IME = 0x4
    VOICE = 0x8
    PTT_ASSISTANT = 0x10
    POWER = 0x20
    VOLUME = 0x40
    GAMEPAD = 0x100
    AUDIO_DEVICES = 0x200
    FIND_MY_REMOTE = 0x400
    APP_LINK = 0x800


# --------------------------------------------------------------------------
# low-level varint / field helpers
# --------------------------------------------------------------------------


def encode_varint(value: int) -> bytes:
    if value < 0:
        value += 1 << 64
    out = bytearray()
    while True:
        bits = value & 0x7F
        value >>= 7
        if value:
            out.append(bits | 0x80)
        else:
            out.append(bits)
            return bytes(out)


def decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise ValueError("truncated varint")
        b = data[offset]
        offset += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            return result, offset


def encode_tag(field_number: int, wire_type: int) -> bytes:
    return encode_varint((field_number << 3) | wire_type)


def delimited(message: bytes) -> bytes:
    """protobuf writeDelimitedTo framing (APK evidence: asrs.handleMessage)."""
    return encode_varint(len(message)) + message


def _field(field_number: int, wire_type: int, payload: bytes) -> bytes:
    return encode_tag(field_number, wire_type) + payload


def varint_field(field_number: int, value: int) -> bytes:
    return _field(field_number, 0, encode_varint(value))


def bytes_field(field_number: int, value: bytes) -> bytes:
    return _field(field_number, 2, encode_varint(len(value)) + value)


def message_field(field_number: int, encoded: bytes) -> bytes:
    return _field(field_number, 2, encode_varint(len(encoded)) + encoded)


def walk_fields(data: bytes) -> Iterator[tuple[int, int, bytes]]:
    """Yield (field_number, wire_type, raw_value) for every field in order."""
    offset = 0
    while offset < len(data):
        key, offset = decode_varint(data, offset)
        number, wire_type = key >> 3, key & 7
        if wire_type == 0:
            value, offset = decode_varint(data, offset)
            yield number, wire_type, encode_varint(value)
        elif wire_type == 1:
            yield number, wire_type, data[offset : offset + 8]
            offset += 8
        elif wire_type == 2:
            length, offset = decode_varint(data, offset)
            yield number, wire_type, data[offset : offset + length]
            offset += length
        elif wire_type == 5:
            yield number, wire_type, data[offset : offset + 4]
            offset += 4
        else:
            raise ValueError(f"unsupported wire type {wire_type}")


def parse_fields(data: bytes) -> dict[int, tuple[int, bytes]]:
    return {number: (wire_type, value) for number, wire_type, value in walk_fields(data)}


# --------------------------------------------------------------------------
# messages used by this client
# --------------------------------------------------------------------------


@dataclass
class DeviceInfo:
    """RemoteDeviceInfo (public proto): model=1, vendor=2, unknown1=3,
    unknown2=4, package_name=5, app_version=6.

    APK evidence (asrd.f): the app replies with Build.MODEL / Build.MANUFACTURER
    plus its package name; the TV's variant is logged as build information."""

    model: str = ""
    vendor: str = ""
    unknown1: int = 1
    unknown2: str = "1"
    package_name: str = ""
    app_version: str = ""

    def encode(self) -> bytes:
        out = bytearray()
        if self.model:
            out += bytes_field(1, self.model.encode())
        if self.vendor:
            out += bytes_field(2, self.vendor.encode())
        if self.unknown1:
            out += varint_field(3, self.unknown1)
        if self.unknown2:
            out += bytes_field(4, self.unknown2.encode())
        if self.package_name:
            out += bytes_field(5, self.package_name.encode())
        if self.app_version:
            out += bytes_field(6, self.app_version.encode())
        return bytes(out)

    @classmethod
    def decode(cls, data: bytes) -> "DeviceInfo":
        info = cls()
        for number, wire_type, value in walk_fields(data):
            if wire_type != 2 and number != 3:
                continue
            if number == 1:
                info.model = value.decode("utf-8", "replace")
            elif number == 2:
                info.vendor = value.decode("utf-8", "replace")
            elif number == 3 and wire_type == 0:
                info.unknown1, _ = decode_varint(value)
            elif number == 4:
                info.unknown2 = value.decode("utf-8", "replace")
            elif number == 5:
                info.package_name = value.decode("utf-8", "replace")
            elif number == 6:
                info.app_version = value.decode("utf-8", "replace")
        return info


@dataclass
class Configure:
    """RemoteConfigure: code1=1 (capability mask), device_info=2."""

    code1: int = 0
    device_info: DeviceInfo | None = None

    def encode(self) -> bytes:
        out = bytearray()
        if self.code1:
            out += varint_field(1, self.code1)
        if self.device_info is not None:
            out += message_field(2, self.device_info.encode())
        return bytes(out)

    @classmethod
    def decode(cls, data: bytes) -> "Configure":
        cfg = cls()
        for number, wire_type, value in walk_fields(data):
            if number == 1 and wire_type == 0:
                cfg.code1, _ = decode_varint(value)
            elif number == 2 and wire_type == 2:
                cfg.device_info = DeviceInfo.decode(value)
        return cfg


@dataclass
class KeyInject:
    """RemoteKeyInject (APK class asvg): key_code=1, direction=2."""

    key_code: int
    direction: Direction = Direction.SHORT

    def encode(self) -> bytes:
        return varint_field(1, self.key_code) + varint_field(2, int(self.direction))


@dataclass
class VoiceBegin:
    """RemoteVoiceBegin: session_id=1, package_name=2."""

    session_id: int
    package_name: str = ""

    def encode(self) -> bytes:
        out = varint_field(1, self.session_id)
        if self.package_name:
            out += bytes_field(2, self.package_name.encode())
        return out


@dataclass
class VoicePayload:
    """RemoteVoicePayload: session_id=1, samples=2 (bytes)."""

    session_id: int
    samples: bytes

    def encode(self) -> bytes:
        return varint_field(1, self.session_id) + bytes_field(2, self.samples)


@dataclass
class VoiceEnd:
    """RemoteVoiceEnd: session_id=1."""

    session_id: int

    def encode(self) -> bytes:
        return varint_field(1, self.session_id)


@dataclass
class ImeBatchEdit:
    """RemoteImeBatchEdit: ime_counter=1, field_counter=2, edit_info=3
    (RemoteEditInfo: insert=1, text_field_status=2 = RemoteImeObject
    {start=1, end=2, value=3})."""

    ime_counter: int
    field_counter: int
    insert: int = 1
    text: str = ""

    def encode(self) -> bytes:
        param_value = max(len(self.text) - 1, 0)
        ime_object = (
            varint_field(1, param_value)
            + varint_field(2, param_value)
            + bytes_field(3, self.text.encode())
        )
        edit_info = varint_field(1, self.insert) + message_field(2, ime_object)
        return (
            varint_field(1, self.ime_counter)
            + varint_field(2, self.field_counter)
            + message_field(3, edit_info)
        )


@dataclass
class PingRequest:
    """RemotePingRequest: val1=1, val2=2."""

    val1: int = 0
    val2: int = 0


@dataclass
class AppLinkLaunch:
    """RemoteAppLinkLaunchRequest: app_link=1."""

    app_link: str

    def encode(self) -> bytes:
        return bytes_field(1, self.app_link.encode())


# --------------------------------------------------------------------------
# the envelope
# --------------------------------------------------------------------------

# RemoteMessage oneof field numbers (public proto; APK evidence agrees).
F_CONFIGURE = 1
F_SET_ACTIVE = 2
F_ERROR = 3
F_PING_REQUEST = 8
F_PING_RESPONSE = 9
F_KEY_INJECT = 10
F_IME_KEY_INJECT = 20
F_IME_BATCH_EDIT = 21
F_IME_SHOW_REQUEST = 22
F_VOICE_BEGIN = 30
F_VOICE_PAYLOAD = 31
F_VOICE_END = 32
F_START = 40
F_SET_VOLUME = 50
F_ADJUST_VOLUME = 51
F_SET_AUDIO_DEVICE = 60
F_RESET_AUDIO_DEVICE = 61
F_APP_LINK = 90


@dataclass
class OutboundMessage:
    """Builds one outbound RemoteMessage envelope.

    Exactly one oneof member is set per message, like protobuf oneof semantics."""

    payload: bytes = b""

    @classmethod
    def configure(cls, cfg: Configure) -> "OutboundMessage":
        return cls(message_field(F_CONFIGURE, cfg.encode()))

    @classmethod
    def set_active(cls, mask: int) -> "OutboundMessage":
        return cls(varint_field(F_SET_ACTIVE, mask))

    @classmethod
    def ping_response(cls, val1: int) -> "OutboundMessage":
        return cls(varint_field(F_PING_RESPONSE, val1))

    @classmethod
    def key_inject(cls, key: KeyInject) -> "OutboundMessage":
        return cls(message_field(F_KEY_INJECT, key.encode()))

    @classmethod
    def ime_batch_edit(cls, edit: ImeBatchEdit) -> "OutboundMessage":
        return cls(message_field(F_IME_BATCH_EDIT, edit.encode()))

    @classmethod
    def voice_begin(cls, begin: VoiceBegin) -> "OutboundMessage":
        return cls(message_field(F_VOICE_BEGIN, begin.encode()))

    @classmethod
    def voice_payload(cls, payload: VoicePayload) -> "OutboundMessage":
        return cls(message_field(F_VOICE_PAYLOAD, payload.encode()))

    @classmethod
    def voice_end(cls, end: VoiceEnd) -> "OutboundMessage":
        return cls(message_field(F_VOICE_END, end.encode()))

    @classmethod
    def app_link(cls, link: AppLinkLaunch) -> "OutboundMessage":
        return cls(message_field(F_APP_LINK, link.encode()))

    def encode(self) -> bytes:
        return self.payload


@dataclass
class InboundMessage:
    """Parsed inbound RemoteMessage. ``oneof`` holds the wire field number."""

    oneof: int
    fields: dict[int, tuple[int, bytes]] = field(default_factory=dict)

    def raw(self, number: int) -> bytes | None:
        entry = self.fields.get(number)
        return entry[1] if entry else None

    def configure(self) -> Configure | None:
        raw = self.raw(F_CONFIGURE)
        return Configure.decode(raw) if raw is not None else None

    def set_active(self) -> int | None:
        raw = self.raw(F_SET_ACTIVE)
        if raw is None:
            return None
        value, _ = decode_varint(raw)
        return value

    def started(self) -> bool | None:
        raw = self.raw(F_START)
        if raw is None:
            return None
        for number, wire_type, value in walk_fields(raw):
            if number == 1 and wire_type == 0:
                value, _ = decode_varint(value)
                return bool(value)
        return None

    def ping_request(self) -> PingRequest | None:
        raw = self.raw(F_PING_REQUEST)
        if raw is None:
            return None
        ping = PingRequest()
        for number, wire_type, value in walk_fields(raw):
            if wire_type == 0:
                value, _ = decode_varint(value)
                if number == 1:
                    ping.val1 = value
                elif number == 2:
                    ping.val2 = value
        return ping

    def voice_session_id(self) -> int | None:
        raw = self.raw(F_VOICE_BEGIN)
        if raw is None:
            return None
        for number, wire_type, value in walk_fields(raw):
            if number == 1 and wire_type == 0:
                value, _ = decode_varint(value)
                return value
        return None

    def ime_counters(self) -> tuple[int, int] | None:
        raw = self.raw(F_IME_BATCH_EDIT)
        if raw is None:
            return None
        counters = [0, 0]
        for number, wire_type, value in walk_fields(raw):
            if wire_type == 0 and number in (1, 2):
                counters[number - 1], _ = decode_varint(value)
        return counters[0], counters[1]

    def current_app(self) -> str | None:
        raw = self.raw(F_IME_KEY_INJECT)
        if raw is None:
            return None
        for number, wire_type, value in walk_fields(raw):
            if number == 1 and wire_type == 2:  # RemoteAppInfo
                for n2, wt2, v2 in walk_fields(value):
                    if n2 == 12 and wt2 == 2:  # app_package
                        return v2.decode("utf-8", "replace")
        return None

    def volume(self) -> dict[str, int | bool] | None:
        raw = self.raw(F_SET_VOLUME)
        if raw is None:
            return None
        info: dict[str, int | bool] = {}
        for number, wire_type, value in walk_fields(raw):
            if wire_type == 0:
                value, _ = decode_varint(value)
                if number == 6:
                    info["max"] = value
                elif number == 7:
                    info["level"] = value
                elif number == 8:
                    info["muted"] = bool(value)
        return info or None


def parse_inbound(data: bytes) -> InboundMessage:
    fields = parse_fields(data)
    # The oneof case is the single field present on the wire; pick the last
    # listed field (protobuf serializes one member at a time).
    oneof = max(fields) if fields else 0
    return InboundMessage(oneof=oneof, fields=fields)
