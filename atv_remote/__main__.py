"""OpenRemote — standalone Google TV / Android TV remote control.

Commands:
  openremote discover                 list TVs on the local network
  openremote pair --host H [--port P] pair with a TV (PIN shown on the TV)
  openremote remote --host H [--port P]
                                      start the interactive remote
"""

from __future__ import annotations

import argparse
import asyncio
import pathlib
import sys

from .client import ATVRemoteClient, RemoteConfig
from .discovery import discover
from .pairing import PairingClient, make_ssl_context
from .certs import ensure_client_cert


def _config_from(args: argparse.Namespace) -> RemoteConfig:
    return RemoteConfig(
        host=args.host,
        port=args.port,
        client_name=args.name,
        cert_path=args.cert or "~/.config/openremote/client.pem",
        key_path=args.key or "~/.config/openremote/key.pem",
    )


async def cmd_discover(args: argparse.Namespace) -> int:
    print(f"Searching for {_SERVICE} ({args.timeout}s)...")
    devices = await discover(timeout=args.timeout)
    if not devices:
        print("No TVs found. Make sure the TV is on the same network and that")
        print("'Android TV Remote Service' is enabled on it.")
        return 1
    for device in devices:
        standby = "" if device.standby is None else f" standby={device.standby}"
        print(f"  {device.name:40s} {device.host}:{device.port}{standby}")
    print("\nPair with:  openremote pair --host <ip>")
    return 0


_SERVICE = "_androidtvremote2._tcp"


async def cmd_pair(args: argparse.Namespace) -> int:
    config = _config_from(args)
    cert_path, key_path = ensure_client_cert(
        pathlib.Path(config.cert_path).expanduser(),
        pathlib.Path(config.key_path).expanduser(),
    )
    ctx = make_ssl_context(str(cert_path), str(key_path))
    print(f"Connecting to {config.host}:{config.port} ...")
    reader, writer = await asyncio.open_connection(config.host, config.port, ssl=ctx)
    pairing = PairingClient(reader, writer, config.client_name, cert_path.read_bytes())
    print("Starting pairing; a 6-digit PIN should appear on the TV...")
    await pairing.start()
    pin = input("Enter the PIN shown on the TV: ").strip()
    try:
        await pairing.finish(pin)
    except ValueError as exc:
        print(f"Pairing failed: {exc}", file=sys.stderr)
        return 1
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, OSError):
        pass
    print(f"Paired. Client certificate saved to {cert_path}")
    print("Now run:  openremote remote --host " + config.host)
    return 0


async def cmd_remote(args: argparse.Namespace) -> int:
    from .ui import run_ui

    config = _config_from(args)
    client = ATVRemoteClient(config)
    streamer = None
    if not args.no_voice:
        try:
            from .voice import VoiceStreamer

            streamer = VoiceStreamer(client.send_voice_chunk)
        except RuntimeError as exc:
            print(f"voice disabled: {exc}", file=sys.stderr)
    await client.connect()
    try:
        await run_ui(client, streamer)
    finally:
        if streamer:
            await streamer.stop()
        await client.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="openremote", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--host", help="TV IP address or hostname")
        p.add_argument("--port", type=int, default=6467,
                       help="remote service port (from mDNS; default 6467)")
        p.add_argument("--name", default="OpenRemote", help="client name shown on the TV")
        p.add_argument("--cert", help="client certificate PEM path")
        p.add_argument("--key", help="client key PEM path")

    p_discover = sub.add_parser("discover", help="find TVs via mDNS")
    p_discover.add_argument("--timeout", type=float, default=5.0)
    p_discover.set_defaults(func=cmd_discover)

    p_pair = sub.add_parser("pair", help="pair with a TV using the PIN shown on it")
    common(p_pair)
    p_pair.set_defaults(func=cmd_pair)

    p_remote = sub.add_parser("remote", help="start the interactive remote")
    common(p_remote)
    p_remote.add_argument("--no-voice", action="store_true", help="disable mic streaming")
    p_remote.set_defaults(func=cmd_remote)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return asyncio.run(args.func(args))
    except KeyboardInterrupt:
        return 130
    except ConnectionError as exc:
        print(f"connection error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
