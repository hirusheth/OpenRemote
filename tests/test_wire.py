"""Wire codec tests: byte-exact protobuf encoding and parsing round-trips."""

from atv_remote import wire


def test_varint_roundtrip() -> None:
    for value in (0, 1, 127, 128, 300, 2**20, 2**31, 2**63):
        encoded = wire.encode_varint(value)
        decoded, offset = wire.decode_varint(encoded, 0)
        assert decoded == value
        assert offset == len(encoded)


def test_delimited_framing() -> None:
    payload = b"hello"
    framed = wire.delimited(payload)
    assert framed == b"\x05hello"


def test_key_inject_encoding() -> None:
    # RemoteMessage.remote_key_inject = field 10, message RemoteKeyInject
    # {key_code = 1 (varint), direction = 2 (varint)}.
    message = wire.OutboundMessage.key_inject(
        wire.KeyInject(key_code=26, direction=wire.Direction.SHORT)
    )
    encoded = message.encode()
    assert encoded == bytes.fromhex("5204081a1003")
    # field 10 wire 2 -> tag 0x52, len 4, then key_code=26 (08 1a),
    # direction=SHORT(3) (10 03)


def test_configure_roundtrip() -> None:
    cfg = wire.Configure(
        code1=0x7F,
        device_info=wire.DeviceInfo(model="m", vendor="v", package_name="p"),
    )
    message = wire.OutboundMessage.configure(cfg)
    fields = wire.parse_fields(message.encode())
    assert list(fields) == [wire.F_CONFIGURE]
    decoded = wire.Configure.decode(fields[wire.F_CONFIGURE][1])
    assert decoded.code1 == 0x7F
    assert decoded.device_info.model == "m"
    assert decoded.device_info.vendor == "v"
    assert decoded.device_info.package_name == "p"


def test_inbound_parse_ping() -> None:
    # server: remote_ping_request (field 8) {val1 = 1234}
    # envelope: tag 0x42 (field 8, wire 2), len 3, payload 08 d2 09
    payload = bytes.fromhex("420308d209")
    message = wire.parse_inbound(payload)
    assert message.oneof == wire.F_PING_REQUEST
    ping = message.ping_request()
    assert ping is not None and ping.val1 == 1234


def test_inbound_parse_started() -> None:
    # server: remote_start (field 40) {started = true}
    payload = wire.message_field(40, wire.varint_field(1, 1))
    message = wire.parse_inbound(payload)
    assert message.oneof == wire.F_START
    assert message.started() is True


def test_inbound_voice_begin() -> None:
    payload = wire.message_field(30, wire.varint_field(1, 77))
    message = wire.parse_inbound(payload)
    assert message.oneof == wire.F_VOICE_BEGIN
    assert message.voice_session_id() == 77


def test_pairing_secret_shape() -> None:
    # The PIN-hash check must reject a wrong PIN deterministically.
    import pytest

    from atv_remote.pairing import pairing_secret

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone

    def make_cert() -> bytes:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t")])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM)

    client_pem = make_cert()
    server_der = x509.load_pem_x509_certificate(make_cert()).public_bytes(
        serialization.Encoding.DER
    )
    with pytest.raises(ValueError):
        pairing_secret(client_pem, server_der, "zzzzzz")
