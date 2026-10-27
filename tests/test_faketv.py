"""End-to-end tests against the Fake TV emulator: pairing + remote + voice."""

import asyncio

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from atv_remote.certs import ensure_client_cert, generate_client_cert
from atv_remote.client import ATVRemoteClient, RemoteConfig
from atv_remote.faketv import FakeTV
from atv_remote.keys import KeyCode
from atv_remote.pairing import (
    PairingClient,
    make_pairing_pin,
    make_ssl_context,
    pairing_secret,
    server_pairing_secret,
)


@pytest.fixture()
def cert_paths(tmp_path):
    return ensure_client_cert(tmp_path / "c.pem", tmp_path / "k.pem")


@pytest.fixture()
async def tv(cert_paths):
    fake = FakeTV(
        name="Fake TV",
        port=0,
        advertise=False,
        client_cert_pem=open(cert_paths[0], "rb").read(),
    )
    await fake.start()
    yield fake
    await fake.stop()


async def _pair_with(tv, cert_path, key_path, pin_override=None):
    """Run a real POLO pairing against the emulator over TLS."""
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", tv.port, ssl=make_ssl_context(str(cert_path), str(key_path))
    )
    try:
        cert_pem = open(cert_path, "rb").read()
        pairing = PairingClient(reader, writer, "TestClient", cert_pem)
        await pairing.start()
        pin = pin_override if pin_override is not None else tv.last_pin
        await pairing.finish(pin)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


@pytest.mark.asyncio
async def test_pairing_roundtrip(tv, cert_paths):
    """The emulator generates a valid PIN and verifies the client's secret."""
    await _pair_with(tv, *cert_paths)
    assert tv.stats.pairings_ok == 1
    assert tv.last_pin is not None and len(tv.last_pin) == 6


@pytest.mark.asyncio
async def test_pairing_rejects_malformed_pin(tv, cert_paths):
    """A PIN failing the check-digit rule is rejected before sending."""
    with pytest.raises(ValueError):
        await _pair_with(tv, *cert_paths, pin_override="000000")
    assert tv.stats.pairings_ok == 0


@pytest.mark.asyncio
async def test_remote_session_keys_text_and_state(tv, cert_paths):
    """Connect, send a key and text, and read the TV's pushed state."""
    config = RemoteConfig(
        host="127.0.0.1",
        port=tv.port,
        cert_path=str(cert_paths[0]),
        key_path=str(cert_paths[1]),
    )
    client = ATVRemoteClient(config)
    await client.connect()
    try:
        # The emulator pushed its identity and state on connect.
        assert client.state.device_info is not None
        assert client.state.device_info.model == "FakeTV"
        assert client.state.is_on is True
        assert client.state.volume == {"max": 15, "level": 10, "muted": False}

        await client.tap_key(KeyCode.POWER)
        await asyncio.sleep(0.2)
        assert tv.stats.keys.get("power") == 1

        await client.send_text("hello")
        await asyncio.sleep(0.2)
        assert tv.stats.texts == ["hello"]
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_voice_session(tv, cert_paths):
    """KEYCODE_SEARCH opens a voice session; PCM chunks arrive at the TV."""
    config = RemoteConfig(
        host="127.0.0.1",
        port=tv.port,
        cert_path=str(cert_paths[0]),
        key_path=str(cert_paths[1]),
    )
    client = ATVRemoteClient(config)
    await client.connect()
    try:
        session_id = await client.start_voice()
        assert session_id == 1
        await client.send_voice_chunk(b"\x00" * 8192)
        await client.end_voice()
        await asyncio.sleep(0.2)
        assert tv.stats.voice_sessions == 1
        assert tv.stats.voice_bytes >= 8192
    finally:
        await client.close()


def test_generated_pin_satisfies_the_secret_rule():
    """A TV-generated PIN must validate under the client-side secret rule."""
    cert_pem, _key_pem = generate_client_cert("pin-test")
    der = x509.load_pem_x509_certificate(cert_pem).public_bytes(Encoding.DER)
    pin = make_pairing_pin(der, cert_pem)
    assert len(pin) == 6
    digest = pairing_secret(cert_pem, der, pin)  # raises on check-digit mismatch
    assert digest == server_pairing_secret(der, cert_pem, pin)
